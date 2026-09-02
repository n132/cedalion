> Machine-generated root-cause analysis. No human has reviewed it and it
> may be wrong. It is not a patch submission, and nothing in it should be
> taken as ground truth. What we do and do not verify:
> https://bugs.sh/reporting.html

# net/mac80211: use-after-free of a link STA's group keys (`ieee80211_remove_link_keys`)

## 1. Bug identity

| | |
|---|---|
| Bug type | slab-use-after-free (read), plus linked-list corruption / potential UAF write |
| Crash function | `ieee80211_remove_link_keys()` — `net/mac80211/key.c` |
| Root-cause functions | `sta_remove_link()` (`net/mac80211/sta_info.c`), `ieee80211_key_replace()` (`net/mac80211/key.c`) |
| Introduced by | `ccdde7c74ffd ("wifi: mac80211: properly implement MLO key handling")`, v6.1 |
| Trigger rate | 3/3 — deterministic, single-threaded, no race |

## 2. Root cause

`ieee80211_add_key()` accepts a **group** key with `NL80211_ATTR_MAC` (a station) *and*
`NL80211_ATTR_MLO_LINK_ID` (a link): the pairwise+link combination is rejected
(`WARN_ON(pairwise && link_id >= 0)`, `cfg.c`) but the group+link one is legal MLO usage.
`ieee80211_key_replace()` then stores it in `link_sta->gtk[idx]` and links it into
`sdata->key_list`, with `key->sta = sta` and `key->conf.link_id = L`.

`sta_remove_link()` (`sta_info.c:423`) tears the link STA down — `sta->link[L] = NULL`, the
`link_sta` is freed via RCU — **without touching `link_sta->gtk[]`**. The key survives with
nothing pointing at it but `sdata->key_list`.

From there two independent memory-safety problems follow.

**(a) The key is freed while still on `sdata->key_list`.** All three teardown callers of
`ieee80211_key_replace()` discard its return value and free the key regardless:

```c
/* ieee80211_free_keys_iface(), ieee80211_remove_link_keys() */
list_for_each_entry_safe(key, tmp, &sdata->key_list, list) {
        ieee80211_key_replace(key->sdata, link, key->sta, ..., key, NULL);
        list_add_tail(&key->list, keys);      /* node may still be on sdata->key_list */
}
/* ... then ieee80211_free_key_list() -> __ieee80211_key_destroy() */
```

With `sta->link[L] == NULL`, `ieee80211_key_replace()` takes

```c
        if (sta) {
                link_sta = rcu_dereference_protected(sta->link[link_id], ...);
                if (!link_sta)
                        return -ENOLINK;      /* key.c:487 */
        }
```

which is ~100 lines *before* the `if (old) list_del_rcu(&old->list);` at the end of the
function. The caller then `list_add_tail()`s a node that is still linked into
`sdata->key_list`, and the key is freed. `sdata->key_list` is left holding a freed node.

A single `NL80211_CMD_REMOVE_LINK` is enough to both create and consume the dangling node:
`cfg80211_remove_link()` → `cfg80211_stop_ap()` → `ieee80211_stop_ap()` runs
`ieee80211_remove_link_keys()` (frees the key), and then
`ieee80211_vif_update_links()` → `ieee80211_tear_down_links()` runs
`ieee80211_remove_link_keys()` a second time, whose
`list_for_each_entry_safe(key, tmp, &sdata->key_list, list)` reads the freed node.

**(b) The key also outlives the station.** `ieee80211_free_sta_keys()` walks only
`sta->deflink.gtk[]` and `sta->ptk[]`, so a key installed on a *non-default* link STA is not
reclaimed at station teardown either. `key->sta` is then dangling, and the next
`ieee80211_key_replace(key->sdata, NULL, key->sta, ...)` dereferences the freed `sta` at
`rcu_dereference_protected(sta->link[link_id], lockdep_is_held(&sta->local->hw.wiphy->mtx))`
— a second UAF read, this time of the `struct sta_info`.

## 3. Crash (decoded, `v6.12.62` + this directory's `config`)

```
BUG: KASAN: slab-use-after-free in ieee80211_remove_link_keys (net/mac80211/key.c:1114)
Read of size 8 at addr ffff888028c3c818 by task exploit/5192
CPU: 1 UID: 65534 PID: 5192 Comm: exploit Not tainted 6.12.62 #3
Call Trace:
 kasan_report (mm/kasan/report.c:596)
 ieee80211_remove_link_keys (net/mac80211/key.c:1114)
 ieee80211_vif_update_links (net/mac80211/link.c:192 net/mac80211/link.c:351)
 ieee80211_vif_set_links (net/mac80211/link.c:408)
 cfg80211_remove_link (net/wireless/util.c:2894)
 nl80211_remove_link (net/wireless/nl80211.c:16312)
 genl_family_rcv_msg_doit (net/netlink/genetlink.c:1117)
 netlink_sendmsg (net/netlink/af_netlink.c:1889)
 __x64_sys_sendto (net/socket.c:2222)
The buggy address belongs to the object at ffff888028c3c800
 which belongs to the cache kmalloc-1k of size 1024
The buggy address is located 24 bytes inside of
 freed 1024-byte region      <-- offsetof(struct ieee80211_key, list) == 24
Kernel panic - not syncing: KASAN: panic_on_warn set ...
```

`3cd8b194bf34`) and `crash_vul_repro_6.12.62.log` (this analysis).

## 4. Already patched upstream? No

Static gate over the vulnerable file, from the proven base to the tips fetched 2026-08-24:

```
git log --oneline 3cd8b194bf34..linus/master  -- net/mac80211/key.c
git log --oneline 3cd8b194bf34..wireless/main -- net/mac80211/key.c
  098056028370 wifi: mac80211: allow cipher change on NAN_DATA interfaces
  0128a77a2b0a wifi: mac80211: Allow per station GTK for NAN Data interfaces
```

Neither touches the `-ENOLINK` early returns, `list_del_rcu(&old->list)`, or
`sta_remove_link()`; one relaxes the per-STA-GTK hardware-offload check and the other the
pairwise cipher-change check. Reading `wireless/main:net/mac80211/key.c` directly confirms
both `return -ENOLINK` statements are still ahead of all the unlink bookkeeping, and
`wireless/main:net/mac80211/sta_info.c:sta_remove_link()` still frees the link STA without
looking at `link_sta->gtk[]`. **No fixing commit exists → the bug is live.** Per the
asymmetry rule, no A/B was spent proving "still broken"; the A/B below instead proves the
proposed fix.

## 6. Reachability

Trace from userspace, all verified in `wireless/main`:

| Step | Gate |
|---|---|
| `unshare(CLONE_NEWUSER \| CLONE_NEWNET)` | none (`CONFIG_USER_NS=y` on Ubuntu and kernelCTF) |
| `HWSIM_CMD_NEW_RADIO` (MLO radio) | `.flags = GENL_UNS_ADMIN_PERM` (`mac80211_hwsim_main.c:7073`); family `.netnsok = true` (`:7099`); `wiphy_net_set(hw->wiphy, net)` puts the radio in the caller's netns (`:5689`) |
| `NL80211_CMD_{SET_INTERFACE,ADD_LINK,START_AP,NEW_STATION,ADD_LINK_STA}` | `GENL_UNS_ADMIN_PERM` |
| `NL80211_CMD_NEW_KEY` | `GENL_UNS_ADMIN_PERM` (`nl80211.c:19609`) |
| `NL80211_CMD_REMOVE_LINK_STA` | `GENL_UNS_ADMIN_PERM` (`nl80211.c:20390`) |
| `NL80211_CMD_REMOVE_LINK` | `GENL_UNS_ADMIN_PERM` (`nl80211.c:20369`) |

`GENL_UNS_ADMIN_PERM` means `netlink_ns_capable(skb, net->user_ns, CAP_NET_ADMIN)` — not
`capable()` against `init_user_ns` — so an unprivileged uid that owns a fresh user+net
`unshare(CLONE_NEWUSER|CLONE_NEWNET)` and the KASAN splat fires with `UID: 65534` in the
report header (see `crash_vul_repro_6.12.62.log`).

**Verdict: reachable by an unprivileged user — on a kernel that has an MLO-capable 802.11
driver available.** That last clause is the real-world limiter and is stated honestly below.

### Required kernel config

| Config option | Required | kernelCTF (lts-6.12.92) | Ubuntu (7.0.0-30-generic) |
|---|---|---|---|
| `CONFIG_CFG80211` | yes | not set | `m` |
| `CONFIG_MAC80211` | yes (holds the buggy file) | not set | `m` |
| `CONFIG_USER_NS` | for the unprivileged path | `y` | `y` |
| `CONFIG_MAC80211_HWSIM` | only to get an MLO radio without hardware | not set | `m` |

Notes on what this means in practice:

* **kernelCTF is not affected** — its config has no 802.11 stack at all (`grep 80211
  .config` is empty). The prove stage had to enable `CONFIG_WLAN`/`CFG80211`/`MAC80211`/
  `MAC80211_HWSIM` before the code existed; that is a "make the buggy code present" change,
  not a "make the bug easier to hit" one, and no sanitizer/debug option was added (KASAN,
  `DEBUG_LIST`, `LIST_HARDENED`, `BUG_ON_DATA_CORRUPTION`, `PANIC_ON_OOPS`, `USER_NS` were
  already on).
* **Distro kernels ship `MAC80211=m`**, loaded on any machine with Wi-Fi, so the buggy code
  is present.
* `mac80211_hwsim` is `=m` and **not** auto-loaded; an unprivileged user cannot `modprobe`
  it. Where it *is* loaded (CI, syzkaller, wifi test rigs, containers with the module
  present) the full unprivileged chain works as demonstrated.
* With **real** MLO hardware (iwlwifi/mt76/ath12k in AP mode) the same nl80211 sequence
  reaches the identical code path, but a hardware wiphy lives in `init_net` and moving it to
  another netns needs `CAP_NET_ADMIN` in `init_net`, so that variant is admin-level.
* Independently of any attacker: `REMOVE_LINK_STA` followed by `REMOVE_LINK` with a per-STA
  GTK installed is an **ordinary hostapd MLO teardown sequence**, so this is also a
  spontaneous crash in normal MLO AP operation.

## 7. Local vs remote

**Local.** The trigger is a sequence of generic-netlink commands on an `AF_NETLINK` socket.
No frames are received from the air; nothing on the path parses remote input.

## 8. Race condition?

**Deterministic.** The PoC is single-threaded, uses no `fork()`/threads/signals, and the
(`/exploit-kernel-race`) does not apply. **Disclosure routing: public list** (linux-wireless).

## 9. Severity and impact

| Aspect | Assessment |
|---|---|
| Bug class | slab use-after-free / linked-list corruption |
| Primitive | (i) UAF **read** of a freed `struct ieee80211_key` while walking `sdata->key_list`; (ii) a subsequent `ieee80211_key_link()` does `list_add_tail_rcu(&new->list, &sdata->key_list)`, a UAF **write** through the freed node's `prev->next`; (iii) UAF read of a freed `struct sta_info` via the dangling `key->sta` |
| Corruption target | `struct ieee80211_key` is `kzalloc(sizeof(*key) + key_len)` — the attacker picks the key length and therefore the slab cache (here `kmalloc-1k`) |
| Context | syscall context (`sendto` → genetlink), wiphy mutex held; no softirq/hardirq constraints |
| Input control | medium-high — cache choice via key length; the freed slot can be re-groomed between the free and the re-add, though only serially (everything is under one mutex) |
| Immediate impact | reliable kernel panic (KASAN/`DEBUG_LIST`/`LIST_HARDENED` all fire; without them, a wild list walk) |
| Path to privilege boundary crossing | **plausible** — a linked-list `add` into a groomed freed object is a classic write primitive; grooming is serial, which makes it harder but not implausible |
| Overall severity | **high** where an MLO-capable radio is reachable, **medium** as a general distro exposure (needs `mac80211_hwsim` loaded, or admin-level access to real MLO hardware) |

## 11. Proposed patch

`patch.diff` — `[PATCH wireless] wifi: mac80211: fix use-after-free of a link STA's group keys`
(3 files, +24/−4).

1. `sta_remove_link()` now calls a new `ieee80211_free_link_sta_keys()` **before** the link
   STA is unpublished, so the keys are torn down through the normal path while
   `sta->link[link_id]` and `link_sta->gtk[]` are still valid. This removes the orphan at
   its source and fixes both (a) and (b).
2. `ieee80211_key_replace()` no longer bails out with `-ENOLINK` on the *removal* path when
   the link STA is already gone, so the unlink from `sdata->key_list` always happens; the
   `link` lookup is likewise only fatal when the `!sta` branch — the only code that
   dereferences `link` — will actually run. `rcu_assign_pointer(link_sta->gtk[idx], new)` is
   guarded accordingly. This is the safety net that keeps the list consistent even if some
   other path ever produces an orphan.

`Fixes: ccdde7c74ffd ("wifi: mac80211: properly implement MLO key handling")` — that commit
introduced both the `link_sta->gtk[]` storage and the two `-ENOLINK` early returns.

### A/B verification

Both sides are the same tree (`v6.12.62` = `53d3c6ddbb97`) and the same `.config`
absent because no kernel source was instrumented on either side.

| Side | Kernel | Result |
|---|---|---|


Crucially, **B is not "clean" because the feature broke**: every PoC step still returns `ok`
on the patched kernel, including `NEW_KEY (per-link-STA GTK, link 1)`, `REMOVE_LINK_STA
link 1`, `REMOVE_LINK 1`, the follow-up `NEW_KEY` that exercises the UAF-*write* path
through `list_add_tail_rcu()`, and the interface-down fallback that exercises
`ieee80211_free_keys_iface()`. Installation behaviour is unchanged; only the teardown
bookkeeping is now complete.

### Patch quality

| Review step | Verdict |
|---|---|
| A. Simplicity | Minimal. The only smaller candidate — relaxing `-ENOLINK` alone — fixes the reported crash but leaves problem (b): the key still outlives the station and `key->sta` still dangles. The only other candidate — fixing `sta_remove_link()` alone — leaves `ieee80211_key_replace()`'s `link` lookup able to re-create the same corruption. Both are needed; neither is padding. |
| B. Completeness | `sta_remove_link()` is the single place a `link_sta` is freed (`ieee80211_sta_remove_link()`, `ieee80211_sta_free_link()`, the `ieee80211_sta_activate_link()` error path and `sta_info_free()` all funnel through it), so there is no sibling site to fix. |
| B. Safety | `ieee80211_key_free()` is the same helper `ieee80211_del_key()` uses; it does `synchronize_net()` before the free, which is required here because the key is still reachable via the RCU `link_sta->gtk[]` pointer. Every `sta_remove_link()` caller runs in process context under the wiphy mutex (`lockdep_assert_wiphy()` at the top of the function), so sleeping is legal. The `-ENOLINK` relaxation only affects `new == NULL` (removal); installation behaviour is unchanged, and `ieee80211_key_link()` — the only caller with `new != NULL` — always passes a non-NULL `link`. No new `#include`, no signature changes, no error codes changed for existing callers. |
| C. Overhead | Negligible. `sta_remove_link()` is a control-plane path (link add/remove, station teardown); the added loop is `ARRAY_SIZE(link_sta->gtk)` pointer reads that do nothing unless keys are present. Nothing is added to any TX/RX fast path. |

### Related observation (not fixed here)

`ieee80211_key_switch_links()` (`key.c`) does `WARN_ON(key->sta)` with the comment
*"shouldn't happen for per-link keys"* — but a per-link-STA GTK is exactly a key with
`conf.link_id >= 0` and `key->sta != NULL`, so an active-link switch with such a key
installed trips that `WARN_ON` (a DoS under `panic_on_warn`). It is a separate defect with a
separate fix, deliberately left out of this patch.

## 12. Sending it


| Recipient | Role |
|---|---|
| `johannes@sipsolutions.net` | `--to` — maintainer:MAC80211, also `blamed_fixes 1/1` |
| `linux-wireless@vger.kernel.org` | `--to` — open list:MAC80211 |
| `ilan.peer@intel.com` | `--cc` — `blamed_fixes 1/1` (co-author of `ccdde7c74ffd`) |

`linux-kernel@vger.kernel.org` deliberately dropped in favour of the specific list.
