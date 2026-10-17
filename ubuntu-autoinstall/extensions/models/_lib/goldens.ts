// Generated user-data goldens, built from shared blocks, one per
// storage profile x network. Regenerate with the render tests.

export const IDENTITY_BLOCK = `  "identity":
    "hostname": "web-1"
    "password": "$6$abcdefgh$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "username": "installer"
`;

export const SSH_BLOCK = `  "ssh":
    "allow-pw": false
    "authorized-keys":
      - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTestsPlaceholder000000000000 user@example.com"
    "install-server": true
`;

export const VERSION_BLOCK = `  "version": 1
`;

export const NETWORK_BOND_BLOCK = `  "network":
    "bonds":
      "bond0":
        "addresses":
          - "192.0.2.10/24"
        "interfaces":
          - "eno1"
          - "eno2"
        "nameservers":
          "addresses":
            - "192.0.2.53"
        "parameters":
          "mode": "active-backup"
        "routes":
          - "to": "default"
            "via": "192.0.2.1"
    "ethernets":
      "eno1":
        "dhcp4": false
        "match":
          "macaddress": "02:00:00:00:00:01"
      "eno2":
        "dhcp4": false
        "match":
          "macaddress": "02:00:00:00:00:02"
    "version": 2
`;

export const STORAGE_BLOCKS: Record<string, string> = {
  "lvm": `  "storage":
    "layout":
      "name": "lvm"
      "sizing-policy": "scaled"
`,
  "direct": `  "storage":
    "layout":
      "match":
        "size": "largest"
      "name": "direct"
`,
  "raid1-lvm": `  "storage":
    "config":
      - "grub_device": true
        "id": "disk0"
        "ptable": "gpt"
        "serial": "SERIALA"
        "type": "disk"
        "wipe": "superblock"
      - "device": "disk0"
        "flag": "boot"
        "id": "disk0-esp"
        "preserve": false
        "size": 536870912
        "type": "partition"
      - "device": "disk0"
        "id": "disk0-data"
        "preserve": false
        "size": -1
        "type": "partition"
      - "fstype": "fat32"
        "id": "disk0-esp-fmt"
        "label": "ESP"
        "preserve": false
        "type": "format"
        "volume": "disk0-esp"
      - "device": "disk0-esp-fmt"
        "id": "disk0-esp-mnt"
        "path": "/boot/efi"
        "type": "mount"
      - "grub_device": true
        "id": "disk1"
        "ptable": "gpt"
        "serial": "SERIALB"
        "type": "disk"
        "wipe": "superblock"
      - "device": "disk1"
        "flag": "boot"
        "id": "disk1-esp"
        "preserve": false
        "size": 536870912
        "type": "partition"
      - "device": "disk1"
        "id": "disk1-data"
        "preserve": false
        "size": -1
        "type": "partition"
      - "fstype": "fat32"
        "id": "disk1-esp-fmt"
        "label": "ESP"
        "preserve": false
        "type": "format"
        "volume": "disk1-esp"
      - "devices":
          - "disk0-data"
          - "disk1-data"
        "id": "md0"
        "preserve": false
        "raidlevel": 1
        "spare_devices": []
        "type": "raid"
      - "devices":
          - "md0"
        "id": "vg0"
        "name": "vg0"
        "preserve": false
        "type": "lvm_volgroup"
      - "id": "lv-root"
        "name": "root"
        "preserve": false
        "size": "20G"
        "type": "lvm_partition"
        "volgroup": "vg0"
      - "fstype": "ext4"
        "id": "lv-root-fmt"
        "preserve": false
        "type": "format"
        "volume": "lv-root"
      - "device": "lv-root-fmt"
        "id": "lv-root-mnt"
        "path": "/"
        "type": "mount"
`,
  "raid10-lvm": `  "storage":
    "config":
      - "grub_device": true
        "id": "diska"
        "serial": "SERIALA"
        "type": "disk"
      - "id": "diskb"
        "serial": "SERIALB"
        "type": "disk"
      - "id": "diskc"
        "serial": "SERIALC"
        "type": "disk"
      - "id": "diskd"
        "serial": "SERIALD"
        "type": "disk"
      - "device": "diska"
        "flag": "boot"
        "id": "espa"
        "size": 536870912
        "type": "partition"
      - "device": "diska"
        "id": "dat-a"
        "size": -1
        "type": "partition"
      - "device": "diskb"
        "id": "dat-b"
        "size": -1
        "type": "partition"
      - "device": "diskc"
        "id": "dat-c"
        "size": -1
        "type": "partition"
      - "device": "diskd"
        "id": "dat-d"
        "size": -1
        "type": "partition"
      - "fstype": "fat32"
        "id": "espafmt"
        "type": "format"
        "volume": "espa"
      - "device": "espafmt"
        "id": "espamnt"
        "path": "/boot/efi"
        "type": "mount"
      - "devices":
          - "dat-a"
          - "dat-b"
          - "dat-c"
          - "dat-d"
        "id": "md0"
        "raidlevel": 10
        "spare_devices": []
        "type": "raid"
      - "devices":
          - "md0"
        "id": "vg0"
        "name": "vg0"
        "type": "lvm_volgroup"
      - "id": "lv-root"
        "name": "root"
        "type": "lvm_partition"
        "volgroup": "vg0"
      - "fstype": "ext4"
        "id": "fmt-root"
        "type": "format"
        "volume": "lv-root"
      - "device": "fmt-root"
        "id": "mnt-root"
        "path": "/"
        "type": "mount"
`,
};

export const USER_DATA_GOLDENS: Record<string, string> = (() => {
  const seeds: Record<string, string> = {};
  for (const [profile, storage] of Object.entries(STORAGE_BLOCKS)) {
    for (
      const [net, block] of [
        ["dhcp", ""],
        ["bond", NETWORK_BOND_BLOCK],
      ] as const
    ) {
      seeds[`${profile}__${net}`] = '#cloud-config\n"autoinstall":\n' +
        IDENTITY_BLOCK + block + SSH_BLOCK + storage + VERSION_BLOCK;
    }
  }
  return seeds;
})();
