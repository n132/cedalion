> Machine-generated root-cause analysis. No human has reviewed it and it
> may be wrong. It is not a patch submission, and nothing in it should be
> taken as ground truth. What we do and do not verify:
> https://bugs.sh/reporting.html

# can: peak_usb — slab-out-of-bounds read in `pcan_usb_handle_bus_evt()`

## 1. Bug summary

| | |
|---|---|
| File | `drivers/net/can/usb/peak_usb/pcan_usb.c` |
| Function | `pcan_usb_handle_bus_evt()`, inlined into `pcan_usb_decode_status()` → `pcan_usb_decode_msg()` → `pcan_usb_decode_buf()` |
| Bug class | Slab out-of-bounds **read** (info leak) |
| Faulting line | `pcan_usb.c:563` — `pdev->bec.rxerr = mc->ptr[1];` |
| Context | URB completion handler (softirq) |
| Introduced by | `ea8b33bde76c ("can: pcan_usb: add support of rxerr/txerr counters")`, v5.6 |
| Status upstream | **Not fixed** — present in `net.git` `2f38e26a5741` (2026-08-31) |

## 2. Root cause

`pcan_usb_decode_status()` establishes a **two-byte** bound and immediately consumes both bytes:

```c
	/* check whether function and number can be read */
	if ((mc->ptr + 2) > mc->end)
		return -EINVAL;

	f = mc->ptr[PCAN_USB_CMD_FUNC];
	n = mc->ptr[PCAN_USB_CMD_NUM];
	mc->ptr += PCAN_USB_CMD_ARGS;		/* mc->ptr may now == mc->end */
```

After that advance nothing is known to be in bounds. Every other arm of the dispatch switch
respects this:

* `PCAN_USB_REC_ANALOG` / `PCAN_USB_REC_BUSLOAD` only set `rec_len` and rely on the trailing
  `if ((mc->ptr + rec_len) > mc->end) return -EINVAL;`
* `pcan_usb_decode_ts()` bounds itself (`ptr + 1` / `ptr + 2`)
* `pcan_usb_decode_error()` touches no payload

`PCAN_USB_REC_BUSEVT` is the exception — `pcan_usb_handle_bus_evt()` reads two payload bytes with
nothing validated:

```c
	case PCAN_USB_ERR_CNT_DEC:
	case PCAN_USB_ERR_CNT_INC:
		/* save rx/tx error counters from in the device context */
		pdev->bec.rxerr = mc->ptr[1];		/* up to mc->end + 1 */
		pdev->bec.txerr = mc->ptr[2];		/* up to mc->end + 2 */
		break;
```

The trailing `(mc->ptr + rec_len) > mc->end` check runs only **after** the switch, and for a BUSEVT
record the device controls `rec_len = status_len & PCAN_USB_STATUSLEN_DLC` and can set it to 0, so
that check passes cleanly.

`mc->end` is `ibuf + urb->actual_length`, and the RX buffer is
`kmalloc(dev->adapter->rx_buffer_size)` with `PCAN_USB_RX_BUFFER_SIZE == 64` — an exact
kmalloc-64 object. A device that completes the bulk-IN transfer with `actual_length = 64` and lays
its records out so the final status record's two argument bytes end exactly at offset 64 causes
`ibuf[65]` and `ibuf[66]` to be read out of bounds.

Note the function's own comment ("first byte contains rxerr while 2nd one contains txerr") does not
match the code, which reads indices 1 and 2. That off-by-one was introduced deliberately by
`590eb2b7d8cf ("can: peak_usb: pcan_usb_handle_bus_evt(): fix reading rxerr/txerr values")`; the
missing bound predates it (`ea8b33bde76c` already read `mc->ptr[0]`/`mc->ptr[1]` unchecked), so
`ea8b33bde76c` is the correct `Fixes:` target.

### Leak to userspace

`pdev->bec` is returned by `pcan_usb_get_berr_counter()`, wired as
`priv->do_get_berr_counter`. `can_fill_info()` (`drivers/net/can/dev/netlink.c:1009`) emits it as
`IFLA_CAN_BERR_COUNTER` on **every** `RTM_GETLINK` dump, with no capability check — so any
unprivileged process (`ip -details link show can0`) reads the two out-of-bounds bytes.

## 3. Reachability

Full path, no `capable()` / `ns_capable()` gate anywhere on it:

```
USB device attach (VID 0x0c72 / PID 0x000c)
  -> peak_usb auto-loaded via MODULE_DEVICE_TABLE(usb, peak_usb_table)
  -> pcan_usb_probe() / peak_usb_create_dev()  [answers 2 synchronous GET commands]
  -> can0 configured (bitrate) and brought up  [ordinary device use]
  -> peak_usb_start() submits 4 bulk-IN URBs, each kmalloc(64)
  -> device completes a 64-byte transfer
  -> peak_usb_read_bulk_callback() -> pcan_usb_decode_buf() -> ... -> pcan_usb_handle_bus_evt()
     ^ softirq, entirely device-driven
  -> pdev->bec.rxerr/txerr = OOB bytes
  -> any unprivileged process: RTM_GETLINK -> IFLA_CAN_BERR_COUNTER
```

**Verdict: reachable by an attacker who supplies the peripheral; the read-back needs no privilege
at all.**

Caveat stated plainly: the RX URBs are only submitted from `ndo_open`, so the CAN interface must be
up. That is the normal workflow for a plugged-in PCAN-USB adapter (set bitrate, `ip link set can0
up`) — it is the victim's ordinary use of the device, not a step the attacker must additionally
win. The malicious data lands on the first bulk-IN transfer after open.

In the repro the peripheral is emulated locally with `dummy_hcd` + `raw-gadget`; on a stock Ubuntu
kernel `CONFIG_USB_DUMMY_HCD` is **not** set, so the realistic vector there is a physical or
USB/IP-attached device, not a local unprivileged process.

### Config requirements

| Config option | Required | Repro `config` | Ubuntu 7.0.0-29-generic |
|---|---|---|---|
| `CONFIG_CAN` | yes | `y` | `m` (autoloaded) |
| `CONFIG_CAN_DEV` | yes | `y` | `m` (autoloaded) |
| `CONFIG_CAN_PEAK_USB` | yes | `y` | `m` — autoloaded on attach via modalias |
| `CONFIG_CAN_CALC_BITTIMING` | for the repro's bitrate setup | `y` | `y` |
| `CONFIG_USB_DUMMY_HCD` | repro only | `y` | not set |
| `CONFIG_USB_RAW_GADGET` | repro only | `y` | `m` |

`CONFIG_CAN_PEAK_USB=m` with `MODULE_DEVICE_TABLE` means the driver is auto-loaded when the device
is attached — no prior configuration is needed for the driver to bind.

column could not be filled in.)

## 4. Local vs remote

**Local / peripheral.** Not reachable over the network. The trigger is attacker-controlled data on
a USB bulk-IN endpoint; the read-back is a local unprivileged netlink query. USB/IP
(`CONFIG_USBIP_VHCI_HCD=m` on Ubuntu) makes the *device* remote, but attaching it requires root on
the victim.

## 5. Race condition?

**Deterministic.** No timing dependence, no threads racing on kernel state; the PoC's threads only
emulate the USB peripheral. 2/2 reproductions on the freshly built kernel, 2/2 on the prover's
build. Section 3a (`/exploit-kernel-race`) does not apply.

**Disclosure routing: public list** (`linux-can@vger.kernel.org`).

## 6. Severity and impact

| Aspect | Assessment |
|---|---|
| Bug class | Slab out-of-bounds read (info leak) |
| Primitive | 2 bytes read at `object_end + 1` and `object_end + 2` of a kmalloc-64 object, laundered into `pdev->bec` |
| Input control | High over *which* bytes are read (record padding shifts the cursor), none over their content |
| Immediate impact | Information disclosure of adjacent slab memory; KASAN-visible; no corruption |
| Path to privilege boundary crossing | Unlikely on its own — 2 bytes per transfer, no write primitive. Repeatable at will (one URB per leak), so it can iterate over neighbouring kmalloc-64 objects a couple of bytes at a time; useful as a KASLR/heap-layout oracle feeding another bug |
| Mitigating factors | Read-only; bounded to 2 bytes; requires the CAN interface to be up; on a non-KASAN kernel it silently reads slab bytes rather than faulting |
| Overall severity | **Medium** |

The crash itself is only fatal under `CONFIG_KASAN` with `panic_on_warn`; on a production kernel the
bug is a silent leak, not a DoS.

## 8. Fix status upstream

* Proven-crashing base: `2f38e26a5741` (`net.git`, for-net-2026-08-31), which contains the prover's
  original base `2f1baf1fc892` as an ancestor.
* `git log 2f1baf1fc892..HEAD -- drivers/net/can/usb/peak_usb/pcan_usb.c` yields only email-address
  churn (`d83762005c13`, `f1880f9cc147`) and a treewide timer rename — **no candidate fix**, so no
  cherry-pick A/B was needed.
* The unguarded read is still present verbatim at `pcan_usb.c:563` in that tree.

## 9. Reproduction and verification (A/B)

| | |
|---|---|
| Config | `config` (the prover's config with `CONFIG_DRM_VKMS` disabled — an unrelated `drm_mode_config_validate()` WARN panics this tree at boot under `panic_on_warn`) |


```
BUG: KASAN: slab-out-of-bounds in pcan_usb_decode_buf (drivers/net/can/usb/peak_usb/pcan_usb.c:563)
Read of size 1 at addr ffff8880253816c1 by task swapper/1/0
 kasan_report (mm/kasan/report.c:595)
 pcan_usb_decode_buf (drivers/net/can/usb/peak_usb/pcan_usb.c:563)
 peak_usb_read_bulk_callback (drivers/net/can/usb/peak_usb/pcan_usb_core.c:267)
 __usb_hcd_giveback_urb (drivers/usb/core/hcd.c:1657)
 usb_hcd_giveback_urb (drivers/usb/core/hcd.c:1741)
 __hrtimer_run_queues (kernel/time/hrtimer.c:2067)
 handle_softirqs (kernel/softirq.c:645)

Allocated by task 5007:
 __kmalloc_noprof
 peak_usb_ndo_open
 __dev_open ... devinet_ioctl ... __x64_sys_ioctl

The buggy address is located 1 bytes to the right of
 allocated 64-byte region [ffff888025381680, ffff8880253816c0)
```

`0x6c1 - 0x680 = 65` — exactly `mc->ptr[1]` with `mc->ptr == mc->end == ibuf + 64`. The allocation
site is `peak_usb_ndo_open()`, i.e. the RX transfer buffer, confirming the object identity.


* no KASAN report, no oops; the guest boots to a shell
* all four poisoned 64-byte transfers are delivered and accepted by the gadget
* `IFLA_CAN_BERR_COUNTER` reads back `rxerr=0x00 txerr=0x00` — the counters are simply never
  populated, because the malformed record is now rejected with `-EINVAL`
* `peak_usb ... can0: Rx urb aborted (-71)` at teardown is the gadget being unbound, not a fault

Full log: `qemu_output.fix.log`.

spindle was saturated by concurrent builds; a second 25 GB tree copy plus a third full link was not
`+ patch.diff` rebuilds B.

## 10. Proposed patch

`patch.diff` — `[PATCH can] can: peak_usb: fix slab-out-of-bounds read in pcan_usb_handle_bus_evt()`

```c
 	case PCAN_USB_ERR_CNT_DEC:
 	case PCAN_USB_ERR_CNT_INC:
+		if ((mc->ptr + 3) > mc->end)
+			return -EINVAL;

 		/* save rx/tx error counters from in the device context */
 		pdev->bec.rxerr = mc->ptr[1];
```

Two lines, one function. The check is placed inside the counter arm only, so the `default:`
("reserved") arm — which reads nothing — keeps working exactly as before, and a device that sends
the three data bytes the protocol defines is unaffected.

`Fixes: ea8b33bde76c ("can: pcan_usb: add support of rxerr/txerr counters")`.

### Patch quality

| Review step | Verdict |
|---|---|
| A. Simplicity | Minimal — 2 lines, 1 hunk, at the faulting read. Alternatives (setting `rec_len = 3` for BUSEVT, or hoisting the bound into `pcan_usb_decode_status()`) would change cursor advance for all BUSEVT records, i.e. alter behaviour for currently-working input |
| B. Completeness | Complete for this pattern. `pcan_usb_pro.c:741` (`rec_ptr + sizeof_rec > msg_end`) and `pcan_usb_fd.c:758,773` already bound their records; no sibling instance exists. One *distinct* defect remains in the same file — see below |
| B. Safety | Safe — returns `-EINVAL` on a path that already returns `-EINVAL` for short records; `pcan_usb_decode_status()` propagates it and `pcan_usb_decode_msg()` ends the loop. No allocation, lock or refcount is held at that point, so no leak or imbalance |
| C. Overhead | Negligible — one pointer comparison, only on BUSEVT error-counter records, in a URB completion path that is already doing per-record bounds checks |

### Known second defect, not covered by this patch

`pcan_usb_decode_msg()` drives its loop off the device-supplied record count with no cursor bound
at the loop head:

```c
	struct pcan_usb_msg_context mc = {
		.rec_cnt = ibuf[1],		/* device-supplied, never validated against lbuf */
		...
	};
	for (err = 0; mc.rec_idx < mc.rec_cnt && !err; mc.rec_idx++) {
		u8 sl = *mc.ptr++;		/* no `mc.ptr < mc.end` test */
```

A device that reports more records than the transfer actually contains gets a 1-byte overread at
`mc.end`. This is a real but **separate** bug with a different origin (`46be265d3388`, 2012, the
original driver), it was not exercised by this PoC, and it wants its own patch —
`if (mc.ptr >= mc.end) return -EINVAL;` at the loop head. Folding it into this patch would mix two
logical changes with two different `Fixes:` tags. Recommended as a follow-up.

## 11. Submission


| Recipient | Bucket | Why |
|---|---|---|
| `mkl@pengutronix.de` | `--to` | maintainer: CAN NETWORK DRIVERS |
| `mailhol@kernel.org` | `--to` | maintainer: CAN NETWORK DRIVERS |
| `linux-can@vger.kernel.org` | `--to` | open list: CAN NETWORK DRIVERS |
| `s.grosjean@peak-system.fr` | `--cc` | author of the `Fixes:` commit (current address per `d83762005c13`) |

`get_maintainer.pl --scm` gives `linux-can.git`, hence the `[PATCH can]` subject prefix.
`linux-kernel@vger.kernel.org` deliberately omitted; no reviewers are listed for this subsystem.
