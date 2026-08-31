> Machine-generated root-cause analysis. No human has reviewed it and it
> may be wrong. It is not a patch submission, and nothing in it should be
> taken as ground truth. What we do and do not verify:
> https://bugs.sh/reporting.html

# ath/ar5523: device-controlled `olen` narrowed to `int` defeats the bounds check in `ar5523_read_reply()`

## Summary

| | |
|---|---|
| Bug class | OOB write (kernel stack) + matching OOB read of the source |
| Location | `drivers/net/wireless/ath/ar5523/ar5523.c:83` (`ar5523_read_reply()`, inlined into `ar5523_cmd_rx_cb()`) |
| Introduced by | `b7d572e1871d ("ar5523: Add new driver")`, v3.8 (Oct 2012) |
| Fix status upstream | **Unfixed** at `4e15e89faac9` (netdev/net, 2026-08-21) |
| Trigger | Crafted USB device; automatic on attach, no userspace action |
| Severity | High (remote-of-the-wire DoS / stack corruption from an untrusted peripheral) |

## Root cause

`ar5523_read_reply()` parses a reply the device wrote into `ar->rx_cmd_buf`, a 1024-byte buffer
(`AR5523_MAX_RXCMDSZ`) filled by a bulk-in URB of the same length. Every byte of it is
device-controlled.

```c
	int dlen, olen;                             /* both signed */
	...
	if (dlen >= sizeof(u32)) {
		olen = be32_to_cpu(rp[0]);          /* u32 -> int: sign flip here */
		...
	}

	if (cmd->odata) {
		if (cmd->olen < olen) {             /* int < int: FALSE when olen < 0 */
			...  cmd->res = -EOVERFLOW;  /* rejection branch skipped */
		} else {
			cmd->olen = olen;
			memcpy(cmd->odata, &rp[1], olen);   /* int -> size_t: sign-extends */
			cmd->res = 0;
		}
	}
```

`olen` (`ar5523.c:51`) and `cmd->olen` (`ar5523.h:65`) are both `int`. When the device sets bit 31
of the first payload word, `olen` becomes negative (`INT_MIN` for `0x80000000`). The sole bound is
a comparison **between two ints**, so no promotion to `size_t` rescues it: `4 < INT_MIN` is false,
control takes the success branch, and `memcpy()`'s `size_t` third parameter sign-extends the value
to `0xFFFFFFFF80000000`.

The neighbouring driver `wil6210/wmi.c` writes `if (len > sizeof(reply.cmd.ssid))`, where `sizeof`
promotes the signed operand to `size_t` and a negative length therefore compares as huge and *is*
rejected. ar5523 compares against another `int` field and loses that accidental protection.

`cmd->odata` is always a small stack object — `__be32 rxsize` (4) in `ar5523_get_max_rxsz()`,
`__be32 val_be` (4) in `ar5523_get_capability()`, `u8 macaddr[ETH_ALEN]` (6) in
`ar5523_get_devstatus()`, `ar->serial[16]`. I checked every `ar5523_cmd_read()` call site: the
largest `cmd->olen` is 16, so for **non-negative** `olen` the existing check already keeps the copy
inside the 1024-byte buffer. The negative value is the only memory-safety defect.

`dlen` is not a second bug: `be32_to_cpu(hdr->len) - sizeof(*hdr)` is evaluated in `size_t` and
truncated to `int`, and every wrap case (`hdr->len` of 0, `0xFFFFFFFF`, …) lands negative and is
caught by the existing `if (dlen < 0)`.

## 1. Reachability

The commands that arm `cmd->odata` are issued by `ar5523_probe()` itself, so no userspace action is
needed at all — the whole chain runs in-kernel off the hotplug path:

```
usb hub hotplug -> ar5523_probe() -> ar5523_host_available()      (odata == NULL)
                                  -> ar5523_get_max_rxsz()        (odata = &rxsize, olen = 4)  <-- crash
                                  -> ar5523_get_capability()      (odata = &val_be, olen = 4)
                                  -> ar5523_get_devstatus()       (odata = macaddr,  olen = 6)
       ... reply parsed in ar5523_cmd_rx_cb() (bulk-in URB completion, softirq)
```

There is **no** `capable()` / `ns_capable()` / permission check anywhere on the path. The driver
declares `MODULE_DEVICE_TABLE(usb, ar5523_id_table)`, so udev autoloads it on matching VID/PID —
29 IDs including Netgear WG111T/WPN111, D-Link DWL-AG132, Gigaset, SMC.

The PoC uses VID `0x168c` / PID `0x0001`, the *post*-firmware entry whose `driver_info == 0`, so
`ar5523_probe()` skips `ar5523_load_firmware()` entirely. **No firmware blob is involved** — this is
a crafted-descriptor/crafted-bulk-data device, not a malicious-firmware bug.

Locally the reproducer needs root only to open `/dev/raw-gadget`; that is a property of the
gadget-capable phone).

| Config Option | Required | kernelCTF (lts-6.12.92) | Ubuntu (7.0.0-29-generic) |
|---|---|---|---|
| CONFIG_USB | Yes | not set | `=y` |
| CONFIG_WLAN_VENDOR_ATH | Yes | not set | `=y` |
| CONFIG_ATH_COMMON | Yes | not set | `=m` |
| CONFIG_AR5523 | Yes | not set | **`=m`** (udev-autoloaded) |

kernelCTF's image builds no USB/WLAN stack at all, so it is not reachable there. Ubuntu ships the
driver as an autoloaded module, which is the realistic exposure.

**Verdict: reachable with no local privilege at all** — the attacker needs a USB device, not an
account.

## 2. Local vs Remote

**Local but peripheral-adjacent.** Not reachable over IP. The attacker must present a USB device —
physically, over USB/IP, or from a gadget-capable device plugged into the victim. The kernel then
consumes attacker-controlled bytes with no further interaction.

## 3. Race condition?

**Deterministic.** A pure signedness/bounds logic bug: 4/4 runs in the original prover and 1/1 on my
fresh build, always on the second probe command, ~7.7 s after boot. No threads, no timing. Section
3a (race severity deep-dive) does not apply, so the normal public-list flow is correct.

## 4. Severity and impact

| Aspect | Assessment |
|---|---|
| Bug class | OOB write to kernel stack (plus OOB read of source) |
| Primitive | `memcpy()` of `0xFFFFFFFF80000000` bytes into a 4/6/16-byte stack object |
| Input control | High over *whether* it fires and over the source bytes; **low over the length** |
| Context | Bulk-in URB completion — softirq (`dummy_timer` → `__usb_hcd_giveback_urb`) |
| Immediate impact | Unrecoverable kernel panic; stack and everything above it destroyed |
| Path to privilege boundary crossing | Unlikely as code execution, certain as DoS |
| Overall severity | **High** |

The length is *not* attacker-tunable downward through this path: any positive `olen` larger than
`cmd->olen` is correctly rejected by the same comparison, so only values ≥ 2 GiB get through. The
copy therefore faults long before returning and destroys memory rather than performing a shaped
overwrite. That caps exploitability for code execution but makes it a completely reliable panic.

Observed on the patched-vs-unpatched A/B, the unpatched run shows **both** halves in one boot:
KASAN reports the source-side OOB read first (`__asan_memcpy()` validates `src` before `dest` and
returns without copying), then — KASAN being one-shot — the *next* command runs the real
`__memcpy()` and the machine dies:

```
BUG: KASAN: out-of-bounds in ar5523_cmd_rx_cb (ar5523.c:83)
Read of size 18446744071562067968 at addr ffff88800df00024 by task swapper/1/0
 __asan_memcpy / ar5523_cmd_rx_cb / __usb_hcd_giveback_urb / dummy_timer
...
BUG: unable to handle page fault for address: ffff887f8df0001c
RIP: 0010:memcpy_orig+0x54/0x140
RDX: ffffffff7fffffc0   R13: 0000000080000000
Kernel panic - not syncing: Fatal exception in interrupt
```

`18446744071562067968 == 0xFFFFFFFF80000000 == (size_t)(int)0x80000000`. `R13 = 0x80000000` is the
raw device word; `RDX = 0xffffffff7fffffc0` is the remaining count mid-copy. Faulting address is
`+36` into the 1024-byte `rx_cmd_buf` — exactly `&rp[1]`.

## Fix status verification

- Proven-crashing base: `4e15e89faac9f308baeb01f46c13a051814d2449` (netdev/net, 2026-08-21) — see
- Static gate: `git log $BASE..HEAD -- drivers/net/wireless/ath/ar5523/` shows only treewide
  cleanups (`kmalloc_obj` conversions). `git log --all --grep=ar5523` surfaces the endpoint
  verification fix, the `ar5523_cmd()` UAF fix and the `WDCMSG_TARGET_START` null-deref fix — none
  touches this line.
- Source at HEAD still reads `int dlen, olen;` and `if (cmd->olen < olen)`. **No plausible fixing
  "still broken".
- `git blame` in a full-history tree points at `b7d572e1871d`, and that commit's own
  `ar5523_read_reply()` already contains the identical `int olen` / `cmd->olen < olen` / `memcpy`
  sequence — the bug is original to the driver.

## Proposed patch

`patch.diff` — one line, in `$BUG_DIR/patch.diff`. It folds the negative case into the existing
rejection arm so a malformed reply takes the path the driver already has for an oversized one:

```c
-		if (cmd->olen < olen) {
+		if (olen < 0 || cmd->olen < olen) {
```

### A/B verification

Both kernels built from the same `config` at the same base; they differ by this one line only

|---|---|---|
| KASAN / Oops / panic markers | KASAN OOB → page fault → **Kernel panic** | **0** |
| driver behaviour | unbounded `memcpy`, machine destroyed | `olen too small 4 < -2147483648`; probe fails `-75` (`-EOVERFLOW`) |
| guest survives | no (QEMU exits) | yes (ran to the 300 s timeout) |

The rejection message appears only on the patched build, which independently confirms the intended
kernel booted. `patch.diff` applies cleanly to both the build base and pristine netdev/net HEAD.

### Patch quality

| Review step | Verdict |
|---|---|
| A. Simplicity | Minimal — 1 line, 1 hunk, 1 file. No simpler correct fix exists: the defect is precisely the missing negative case in this comparison. |
| B. Completeness | Complete for this driver. The only other device-length consumer in `ar5523_cmd_rx_cb()` is the `WDCMSG_TARGET_START` arm, which hard-checks `dlen != sizeof(u32)` and copies a fixed 4 bytes — not affected. The same signed-narrowing *pattern* exists elsewhere in-tree, but each is a separate bug and out of scope here. |
| B. Safety | Safe. No new early return, no allocation, no lock, no refcount. Reuses the existing `-EOVERFLOW` path, which callers already handle (`ar5523_cmd()` returns `cmd->res`; probe aborts). Rejects only lengths that are not representable and could never have worked. |
| C. Overhead | Negligible — one signed compare on a per-command control path (a handful of commands per probe), not a data path. |
