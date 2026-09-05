> Machine-generated root-cause analysis. No human has reviewed it and it
> may be wrong. It is not a patch submission, and nothing in it should be
> taken as ground truth. What we do and do not verify:
> https://bugs.sh/reporting.html

# peak_usb / pcan_usb_pro: unvalidated CAN DLC in `pcan_usb_pro_handle_canmsg()`

## 1. Bug

| | |
|---|---|
| File | `drivers/net/can/usb/peak_usb/pcan_usb_pro.c` |
| Functions | `pcan_usb_pro_handle_canmsg()` (:533), reached from `pcan_usb_pro_decode_buf()` (:710) |
| Lines | 554 (`rx->len & 0x0f`), 562 (`memcpy`) |
| Class | slab-out-of-bounds **read** (15 B) + out-of-bounds **write** (7 B, inside skb tailroom) |
| Introduced by | `d8a199355f8f` ("can: usb: PEAK-System Technik PCAN-USB Pro specific part", 2012) |

### Root cause

`pcan_usb_pro_decode_buf()` walks the records in a bulk-IN transfer and bounds each one
**as a container only**:

```c
u16 sizeof_rec = pcan_usb_pro_sizeof_rec[pr->data_type];
if (!sizeof_rec) { ... -ENOTSUPP ... }
if (rec_ptr + sizeof_rec > msg_end) { ... -EBADMSG ... }
```

The table deliberately declares *short* RX-message variants, i.e. the record type is what
says how many payload bytes are actually present:

```c
[PCAN_USBPRO_RXMSG8] = sizeof(struct pcan_usb_pro_rxmsg),      /* 20 -> 8 data bytes */
[PCAN_USBPRO_RXMSG4] = sizeof(struct pcan_usb_pro_rxmsg) - 4,  /* 16 -> 4 data bytes */
[PCAN_USBPRO_RXMSG0] = sizeof(struct pcan_usb_pro_rxmsg) - 8,  /* 12 -> 0 data bytes */
[PCAN_USBPRO_RXRTR]  = sizeof(struct pcan_usb_pro_rxmsg) - 8,  /* 12 -> 0 data bytes */
```

`pcan_usb_pro_handle_canmsg()` then takes the copy length from a *completely separate*
device-supplied nibble and never ties the two together:

```c
can_frame->len = rx->len & 0x0f;            /* 0..15: no clamp, no cross-check */
...
memcpy(can_frame->data, rx->data, can_frame->len);
```

Two independent defects on that one line:

1. **No cross-check against `sizeof_rec`.** A `PCAN_USBPRO_RXMSG0` record is validated as
   12 bytes, yet `rx->data` starts at record offset 12 (`struct pcan_usb_pro_rxmsg` is
   `__packed`) — so the copy source is entirely *outside* the record the loop validated.
   Put that record last in a full 1024-byte transfer and the read runs off the end of the
   `kmalloc(PCAN_USBPRO_RX_BUFFER_SIZE == 1024)` RX buffer allocated in
   `peak_usb_start()` — an exact kmalloc-1k bucket, so byte 1024 is the KASAN redzone.
2. **No clamp to `CAN_MAX_DLEN`.** Every other CAN driver runs the raw DLC through
   `can_cc_dlc2len()` / `can_frame_set_cc_len()`. Here `rx->len & 0x0f` can be 15 while
   `struct can_frame.data` is 8 bytes, so the `memcpy` writes 7 bytes past `cf->data`
   (into skb tailroom — contained, but the frame is then emitted with an invalid
   `cf->len == 15`).

`pcan_usb_pro.c` is the **only** remaining CAN USB driver with this pattern; both siblings
in the same directory already do it correctly — `pcan_usb.c:678` uses
`can_frame_set_cc_len()`, and `pcan_usb_fd.c:569` carries exactly the nested cross-check
this driver lacks (added by `93fcab2c6968`, "can: peak_usb: validate uCAN receive record
lengths", July 2026). That commit fixed `pcan_usb_fd.c` only and left `pcan_usb_pro.c`
behind.

## 2. Already patched upstream? No

- Proven-crashing base from the prover: `2f1baf1fc892` (v7.2-rc7-93).
- `git log 2f1baf1fc892..origin/main -- drivers/net/can/usb/peak_usb/` → **no commits**.
- The one plausible candidate anywhere in the tree, `93fcab2c6968` /
  `89c92a805269` ("can: peak_usb: validate uCAN receive record lengths"), touches
  `pcan_usb_fd.c` only — a different record format and a different function.
- `can_frame->len = rx->len & 0x0f;` is still at line 554 of `origin/main`
  (`6a1094c34d17`, 2026-09-03), and the PoC crashes a kernel freshly built from it.

No A/B was needed: the static gate found no candidate touching this file, and the crash
was reproduced on today's tree.

## 4. Reachability

Path from an attacker-supplied device to the buggy line:

1. Device enumerates as VID `0x0c72` / PID `0x000d` with the five bulk endpoints
   `pcan_usb_pro_probe()` requires (`0x01`, `0x81`, `0x02`, `0x82`, `0x03`).
2. `peak_usb` binds via its `id_table`; udev autoloads the module on the modalias — **no
   local privilege of any kind is required for this step**.
3. Device answers the probe-time vendor control requests (`REQ_INFO`/FW, `REQ_INFO`/BL,
   `REQ_FCT`/DRVLD) with well-formed zero payloads → a `can0` netdev is registered.
4. The link is brought up (`SIOCSIFFLAGS`; needs `CAP_NET_ADMIN` — but on a desktop
   NetworkManager/systemd-networkd will do this for a newly appearing interface, and in
   the PoC it is done locally). `peak_usb_ndo_open()` → `peak_usb_start()` kmallocs the
   1024-byte RX buffer and submits the bulk-IN URBs.
5. The device completes a bulk-IN transfer whose last record is a 12-byte
   `PCAN_USBPRO_RXMSG0` at offset 1012 with `len = 0x0f`. `rec_ptr(1012) + 12 ==
   msg_end(1024)` passes; `memcpy(cf->data, buf + 1024, 15)` fires in softirq context.
6. Any process holding `socket(PF_CAN, SOCK_RAW, CAN_RAW)` on `can0` — **no privilege
   required** — receives the leaked bytes as CAN frame payload.

No capability check exists between the URB completion and the `memcpy`; steps 1–3, 5 are
purely device-driven.

### Config availability

| Config option | Required | kernelCTF (lts-6.12.92) | Ubuntu (7.0.0-30-generic) |
|---|---|---|---|
| `CONFIG_CAN` | Yes | not set | `=m` |
| `CONFIG_CAN_RAW` | to read the leak | not set | `=m` |
| `CONFIG_CAN_PEAK_USB` | Yes | not set | `=m` (udev-autoloaded on VID/PID match) |
| `CONFIG_USB_RAW_GADGET` | only for the local PoC | not set | `=m` |
| `CONFIG_USB_DUMMY_HCD` | only for the local PoC | not set | not set |
| `CONFIG_USBIP_VHCI_HCD` | alternative remote path | not set | `=m` |

Not reachable on the kernelCTF LTS target (`CONFIG_CAN` off). Fully reachable on stock
Ubuntu with a physical or USB/IP device. `CONFIG_USB_DUMMY_HCD` is off on Ubuntu, so the
`raw-gadget`-on-`dummy_hcd` shortcut the PoC uses is a research convenience, not the
production attack path.

**Verdict: reachable by an unprivileged/no-account attacker who can attach a USB device
(physical, or over USB/IP).** No user-namespace trick is involved or needed.

## 5. Local vs remote

**Local but peripheral-adjacent.** The trigger is an attached USB device. `vhci-hcd`
(USB/IP, `=m` on Ubuntu) lets that device live on another host, but importing it is a
privileged local action, so this is not a plain remote bug.

## 6. Race condition?

**Deterministic.** No threads race for the corruption; the PoC crashes 1/1 on the first
deep-dive) does not apply. **Disclosure routing: public list** (`linux-can@vger.kernel.org`).

## 7. Severity and impact

| Aspect | Assessment |
|---|---|
| Bug class | slab-OOB read (15 B) + OOB write (7 B past `cf->data`, inside skb tailroom) |
| Primitive | read of the first ≤15 bytes following a kmalloc-1024 object, delivered verbatim to userspace in a CAN frame; length attacker-chosen 0–15 via the DLC nibble, offset attacker-chosen via record padding |
| Input control | High — record type, record position and DLC are all device-supplied |
| Context | softirq (URB completion, `dummy_timer`/HCD giveback) |
| Immediate impact | **Info disclosure** of adjacent slab memory to an unprivileged process, repeatable at URB rate; **DoS** on hardened kernels (`panic_on_warn`/`oops=panic` turn the FORTIFY report into a panic) |
| Path to privilege boundary crossing | Plausible for the leak (kmalloc-1k neighbours routinely hold pointers → KASLR/heap disclosure). Unlikely for the write: it stays within the skb allocation |
| Mitigating factors | Needs an attached device; leak is capped at 15 bytes per frame; `CONFIG_FORTIFY_SOURCE` turns the write half into a loud WARN |
| Overall severity | **Medium** (CVSS ~6.8, `AV:P/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:H`) |

## 9. Reproduction (A/B)

Both sides built from `net.git` `6a1094c34d176827b2b173e163dcc964a13af93f`
(`7.3.0-rc1-00234-g6a1094c34d17`) with `./config` (KASAN + FORTIFY_SOURCE), driven by


```
memcpy: detected field-spanning write (size 15) of single field "can_frame->data" at drivers/net/can/usb/peak_usb/pcan_usb_pro.c:562 (size 8)
WARNING: drivers/net/can/usb/peak_usb/pcan_usb_pro.c:562 at pcan_usb_pro_decode_buf+0xbf0/0x14d0, CPU#1: swapper/1/0
BUG: KASAN: slab-out-of-bounds in pcan_usb_pro_decode_buf (drivers/net/can/usb/peak_usb/pcan_usb_pro.c:562)
Read of size 15 at addr ffff888030c74c00 by task swapper/1/0
 __asan_memcpy (mm/kasan/shadow.c:105)
 pcan_usb_pro_decode_buf (drivers/net/can/usb/peak_usb/pcan_usb_pro.c:562)
 peak_usb_read_bulk_callback (drivers/net/can/usb/peak_usb/pcan_usb_core.c:267)
 __usb_hcd_giveback_urb (drivers/usb/core/hcd.c:1657)
 usb_hcd_giveback_urb (drivers/usb/core/hcd.c:1741)
The buggy address belongs to the object at ffff888030c74800
 which belongs to the cache kmalloc-1k of size 1024
The buggy address is located 0 bytes to the right of
 allocated 1024-byte region [ffff888030c74800, ffff888030c74c00)
```

Both sanitizers fire on the same line: FORTIFY catches the 15-into-8 write, KASAN catches
shows the buffer coming from `peak_usb_ndo_open()`.

panics over a 5-minute run in which the PoC floods the endpoint continuously. The driver
rejects each malformed record with `-EBADMSG` (`peak_usb ... received usb message` dumps,
913 of them) and keeps resubmitting the URB — the device is simply refused, the interface
stays up.

Note on the environment: `run.sh`'s kernel cmdline had `quiet` removed and
`panic_on_warn=0` added (original kept as `run.sh.orig`). `quiet` suppresses the
`KERN_WARNING`-level FORTIFY line, and `panic_on_warn=1` panics at that WARN *before* the
`memcpy` executes, hiding the KASAN report. Neither change touches the kernel source; with
the stock cmdline the vulnerable kernel panics instead (`qemu_fortify_panic.log`). **No

## 10. Proposed patch

`patch.diff` — `[PATCH] can: peak_usb: validate PCAN-USB Pro receive record lengths`.

```c
-	can_frame->len = rx->len & 0x0f;
+	can_frame_set_cc_len(can_frame, rx->len & 0x0f, dev->can.ctrlmode);
+
+	if (!(rx->flags & PCAN_USBPRO_RTR) &&
+	    sizeof_rec - offsetof(struct pcan_usb_pro_rxmsg, data) <
+	    can_frame->len) {
+		kfree_skb(skb);
+		return -EBADMSG;
+	}
```

`sizeof_rec` is passed down from `pcan_usb_pro_decode_buf()`, which already has it. The
RTR guard matters: an RTR frame legitimately carries a DLC with no payload, so
`PCAN_USBPRO_RXRTR` (12 bytes, 0 data) with `len = 8` must keep working. This is
byte-for-byte the shape of the check `pcan_usb_fd_decode_canmsg()` already uses.

| Review step | Verdict |
|---|---|
| A. Simplicity | Minimal — 12 insertions / 3 deletions, one function plus its single call site. The cross-check subsumes the clamp (`sizeof_rec - 12` is at most 8), but `can_frame_set_cc_len()` is kept so RTR frames, which skip the check, still get a valid `cf->len` |
| B. Completeness | Complete. Swept every `drivers/net/can/usb/**` receive path: `pcan_usb_pro.c` was the last one assigning a raw device DLC to `cf->len`. All others already use `can_cc_dlc2len()`/`can_frame_set_cc_len()`; `pcan_usb_fd.c` and `ems_usb.c` additionally cross-check the DLC against the record size, and `ucan.c` derives the length from the record size outright |
| B. Safety | Safe. Return path is identical to the existing `-EINVAL` (bad `ctrl_idx`) path: `decode_buf()` goes to `fail:`, the caller dumps the buffer and **resubmits the URB** (`pcan_usb_core.c:275`), so no leak, no refcount imbalance, no detach. `kfree_skb()` in softirq is what the sibling driver does. No previously-working input is rejected: a conforming device never sends a DLC larger than the payload its record type declares |
| C. Overhead | Negligible. One subtraction and one compare per received CAN frame, on a USB-URB completion path already doing a `kmalloc` (`alloc_can_skb`) and a `memcpy`. No new locking, no new allocation |

`checkpatch.pl --strict`: 0 errors, 2 warnings — one long line inside the verbatim quoted
