# BIFROST SDK — Gap Census (durable unblocklisted drivers)

Census 2026-09-22: LOLDrivers `drivers.json` (695 entries, 572 vulnerable)
vs MS `VulnerableDriverBlockList.zip` (1660 deny hashes + 172 filename
signals). MS touch by catalog year: 2023 84%, 2024 44%, 2025 29%, 2026 5%.
251 true gaps, 69 cataloged pre-2025 and never absorbed.

Below: the durable-8 (HVCI-TRUE evidence, cert >= 2028, >= 3 samples) with
per-driver patch status — broken version vs fixed version — so you grab a
working copy, not a patched one. Rerun the census any time with the scripts
in `%TEMP%\opencode\census*.py` against fresh downloads.

## 1. asusbsitf.sys (ASUS WinFlash BIOS Flash Driver) — 14 samples

- CVE-2024-33221 (NVD-confirmed, CVSS 7.8): `AsusBSItf.sys` v3.2.12.0.
- Vulnerable: 3.0.10.0, 3.1.10.0, 3.1.25.0, 3.2.11.0, 3.2.12.0.
- Fixed version: **none published**. No ASUS advisory names a fixed build.
  Update via model-specific support page or remove WinFlash if unneeded.
- Still shipping vulnerable: presumed yes (model-gated downloads, no bulletin).
- https://www.loldrivers.io/drivers/9905c737-83ad-4801-a573-8267f3aea924/

## 2. andappsvc2_64.sys (DNP HyperTech CrackProof anti-tamper) — 8 samples

- Ships inside games: Uma Musume Pretty Derby (`Umamusume64_2.sys`),
  iDOLM@STER (`deresute64.sys`), AndApp titles. Same body, 8 filenames,
  version 1.1.0.0, WHQL co-signed, loads despite HVCI.
- CVE: **none assigned**. Vulnerable: 1.1.0.0 (all samples).
- Fixed version: **none published**. No advisory, no updated build.
- Still shipping vulnerable: yes — current game installs drop it, and
  uninstalling the game doesn't always remove the service.
- Entry is titled `deresute64.sys`, search by hash if filename misses:
  https://www.loldrivers.io/drivers/dbd78de7-f5ab-4fb7-a246-39cbcca4678c

## 3. dcprotect.sys (Jiangmen Eyun / DrvCeo) — 8 samples

- Bundled with Chinese `DrvCeo` (Driver President) suite, v1.2.0.0 (all samples).
- CVE: **none assigned**.
- Fixed version: **none published**. Current DrvCeo installer (2.20.0.8,
  2026-04) carries no driver-fix statement — do not treat as patched.
- Still shipping vulnerable: yes by best evidence (unmaintained since ~2020,
  still distributed).
- https://www.loldrivers.io/drivers/7cee2ce8-7881-4a9a-bb18-61587c95f4a2/

## 4. driver_win10.sys aka Filter.sys — THREAT TOOL, not a vendor driver

- No vendor, no product. Dropped by Black Basta-adjacent intrusions (2025).
  One 55KB sample carries a Microsoft WHQL *attestation* signature and loads
  with HVCI on — attestation alone proves nothing about safety.
- CVE: none. Fixed version: N/A — remediation is block + revoke, not update.
- Any presence with no legitimate install path = malicious. Block all three
  known SHA256 + shared imphash; hunt the `Filter.sys` rename.
- https://www.loldrivers.io/drivers/cb9f4425-66de-4371-a3df-3aeec1fda65c

## 5. vboxdrv.sys (Oracle VirtualBox) — 7+7 samples

- CVE-2008-3431 (CISA KEV): VirtualBox before 1.6.4, privilege escalation.
- Vulnerable: 1.6.0/1.6.2 (advisory scope); LOLDrivers also catalogs signed
  2.2.0/2.2.4/3.0.0 builds as block-worthy.
- Fixed: **1.6.4 (Aug 2008)**. Current 7.2.x downloads are fixed lineage.
- Still shipping vulnerable: no (only under Old Builds archives). Old hashes
  on a box without VirtualBox = BYOVD red flag.
- Two entries (both casings): https://www.loldrivers.io/drivers/2da3a276-9e38-4ee6-903d-d15f7c355e7c
  and https://www.loldrivers.io/drivers/79542852-3a0c-43bc-bfa3-3eeb0e1d7fd2

## 6. dsark.sys / DsArk64.sys (Qihoo 360 Total Security DeepScan) — 4 samples

- WHQL Microsoft-signed anti-rootkit driver, 1.0.0.1219–1.1.0.1235.
- CVE for the driver itself: **none** (entry records CVE: NONE; nearby 360
  CVEs hit other components — don't misattribute).
- Fixed version: **none published**. 360 v11.0.0.1314 (Apr 2026) notes no
  driver security changes.
- Still shipping vulnerable: presumed yes (DeepScan still in the product).
- https://www.loldrivers.io/drivers/399fb787-5b06-46f0-86cb-dff7374bb015/

## 7. sfdrvx64.sys (Almico SpeedFan — NOT StarForce) — 3 samples

- CVE-2020-28175 (4.52, CVSS 7.8, vendor never patched) and CVE-2026-19382
  (4.52, vendor did not respond). Older: CVE-2007-5633/5634 (4.33).
- Vulnerable: X2.01.07, X4.43.04, X2.03.11 (driver builds); product 4.52.
- Fixed version: **none** — vendor still offers 4.52 today, copyright
  2000-2020, effectively abandonware. Fresh installs reintroduce it.
- https://www.loldrivers.io/drivers/5a03dc5a-115d-4d6f-b5b5-685f4c014a69

## 8. tprotect — correction: Zemana zam64.sys family, not a standalone driver

- `tProtect.dll` is Sample 13 inside the Zemana `zam64.sys` entry, not its
  own driver. The driver: ZAM Helper Driver (minifilter).
- CVEs on the family: CVE-2018-5713/5714 (2.72.169), CVE-2024-1853/2180/2204,
  CVE-2023-36204/36205, CVE-2022-42045 — advisories state **no patch
  available**. Vendor still offers the affected builds (3.2.28, 2.74.2.664).
- Nothing assigned to `tProtect.dll` itself. Remove the whole ZAM install.
- https://www.loldrivers.io/drivers/e5f12b82-8d07-474e-9587-8c7b3714d60c

## Pattern worth noticing

5 of 8 have **no fix and no vendor response** (ASUS silent, HyperTech silent,
360 silent, Almico abandonware, Zemana abandonware). These gaps don't close
by updating — they close only if Microsoft blocklists them. That's why the
census matters more than the vendor pages.
