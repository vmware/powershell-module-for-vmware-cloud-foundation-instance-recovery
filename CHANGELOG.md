# Release History

## v9.1.1.1001
> Released: 2026-xx-xx
- Added `Get-BackupsFromSFTPServer` to find and interactively select VCF Fleet component backups directly from an SFTP server, with an option to generate a `restore-payload.json`.
- Added `Set-ServicesRuntimeScale`
- Updated `Invoke-VcfOpsVidbVcfInstanceUpdate` to run `vidb-sso-info.sh` and `migrate-vidb-vcf-instance.sh` (replacing `update-vidb-vcf-instance.sh`), matching the documented "Update the Identity Broker VCF Instance Association" procedure. The `-SsoDomainId` parameter is renamed `-SsoRealmId` and is now resolved from the VCF Operations SSO Realms API instead of the legacy `kv_vidb_sso_domain` table.
- Fixed `Invoke-VcfmsFleetComponentRegistration` — Steps 5b/5c of `update_fleet_component_registration.sh` (moving the OPS/OPS_NETWORKS registrations) each prompt for confirmation, but the SSH command piped no stdin past the sudo password, so those prompts always silently defaulted to "skip". Added `-ConfirmOpsMove`/`-ConfirmOpsNetworksMove` switches that answer them explicitly, fed via a pipe nested inside the sudo'd shell (rather than appended after the sudo password on one shared stdin) so it no longer depends on whether `sudo -S` actually consumed a line — it can't if the sudo ticket is already cached, which was still skipping both prompts even with the switches set.

## v9.1.0.1003
> Released: 2026-xx-xx

## v9.1.0.1002
> Released: 2026-06-29
- Initial support for VCF 9.1.0

## v9.0.1
> Released: 2025-09-23
- Initial release of `VMware.CloudFoundation.InstanceRecovery` for VCF 9.x.
