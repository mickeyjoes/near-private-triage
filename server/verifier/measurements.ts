// Workload measurement policy ("accepted workload measurements" in NEAR's
// verification policy). A genuine, up-to-date Intel TDX quote only proves SOME
// TDX guest produced it; these pins make it NEAR AI Cloud's dstack guest:
//
// - OS image: MRTD (TD firmware), RTMR1 (kernel) and RTMR2 (kernel cmdline +
//   initrd) are measured by the TDX module/firmware, not by the guest itself.
// - App identity: dstack measures app-id, the KMS measurement (mr-kms) and the
//   key provider into RTMR3; our RTMR3 replay authenticates those events. The
//   app-id stays stable across NEAR's compose upgrades (observed: the gateway
//   compose changed on 2026-11-13 under the same app-id), so a redeploy by NEAR
//   remains acceptable while a foreign guest or foreign app does not.
//
// Values were observed in genuine NEAR AI Cloud attestations on 2026-11-13 and
// pinned (trust on first use, cross-checked across 22 reports). Unknown values
// yield UNVERIFIED and block disclosure. Review a new NEAR release with
// `npm run pin` and add its values here.

export type Role = 'gateway' | 'model';

export interface OsProfile {
  name: string;
  role: Role;
  mrtd: string;
  rtmr1: string;
  rtmr2: string;
  os_image_hash: string;
}

export interface AppIdentity {
  name: string;
  role: Role;
  app_id: string;
}

export interface MeasurementPolicy {
  os: OsProfile[];
  apps: AppIdentity[];
  mr_kms: string[];
  key_providers: string[];
}

const RTMR1 = '4ae609807c765916a31d724786ed74bcb97e168a9d937b04936aeef2015c907eba5ac352c6bcd749c246fd62ffb659ec';

export const PINNED_MEASUREMENTS: MeasurementPolicy = {
  os: [
    {
      name: 'NEAR AI Cloud gateway · dstack OS (observed 2026-11-13)',
      role: 'gateway',
      mrtd: '7fe60787222bd394cb516abca2435f22f035ab2cc9c0a4b4b3b148e46297f3d931a237b72f359052c6e657d8c1409173',
      rtmr1: RTMR1,
      rtmr2: '764489f277a8540189761e72b4238ba36d4d647e11bd958d8ab5522af2a4867b0ff63e06b0c4967f1857236244040a5d',
      os_image_hash: '8db40cb23008d6213668b5816702d100b37b859a8a5bfd18d938ae3a1b3715bd',
    },
    {
      name: 'NEAR AI Cloud GPU model node · dstack OS (observed 2026-11-13)',
      role: 'model',
      mrtd: 'df4d77c857de652bd0fafa343a2026b51071ee03773d076d283abf1a7d36ff91ffa279ee4a617ac664f7e2a2c8d5891b',
      rtmr1: RTMR1,
      rtmr2: 'bd67ab7554dc27ab03a077bc1447a1a67d0624ff547c4c809a8626f12d6a89712f8ec60e781e99b98208574065d21a71',
      os_image_hash: '91fd5d69ccee3e5ea4f2aeb8c9b632c4358c4ecfc29ba1aa6fb1e402af209829',
    },
  ],
  apps: [
    { name: 'NEAR AI Cloud gateway', role: 'gateway', app_id: 'f550fdfb4eb8ad787c1bcd423f091cbb4a4431ae' },
    { name: 'NEAR AI Cloud model serving', role: 'model', app_id: '2c0a0c96cb6dbd659bf1446e2f3fce58172ff91b' },
  ],
  mr_kms: ['22a6652c0ce74e50b549c0f9c21d53c5861598ec4d58cf3286d158104923bc56'],
  key_providers: [
    '{"name":"kms","id":"3059301306072a8648ce3d020106082a8648ce3d03010703420004394aaed2c745e6a457cb835f7f47423f57ff3ead71b92abff6bdc14d905b319f2e13961b42c50740dae4498d9c51dd7a2e227660c9e5c504083cda06b6c11682"}',
  ],
};
