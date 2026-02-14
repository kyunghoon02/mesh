use embedded_storage::{ReadStorage, Storage};
use esp_partition_table::PartitionTable;
use esp_storage::FlashStorage;

const MAGIC_BYTE: u8 = 0xA5;
const MAGIC_MAC: u8 = 0xB1;
const SLOT_SIZE: usize = 64; // 슬롯 크기(헤더 5B + 데이터)

pub struct StorageManager {
    flash: FlashStorage,
    nvs_offset: u32,
    nvs_size: u32,
}

impl StorageManager {
    pub fn new() -> Self {
        let mut flash = FlashStorage::new();
        let mut table_bin = [0u8; 3072];
        flash.read(0x8000, &mut table_bin).unwrap();

        let table = PartitionTable::iter(&table_bin)
            .filter_map(|p| p.ok())
            .find(|p| p.name() == "mesh_key")
            .expect("Partition 'mesh_key' not found");

        Self {
            flash,
            nvs_offset: table.offset(),
            nvs_size: table.size(),
        }
    }

    pub fn load_key(&mut self) -> Option<[u8; 32]> {
        let (slot_count, _) = self.slot_info();
        let mut best_counter: Option<u32> = None;
        let mut best_key: Option<[u8; 32]> = None;

        for idx in 0..slot_count {
            let mut buf = [0u8; SLOT_SIZE];
            let offset = self.nvs_offset + (idx as u32 * SLOT_SIZE as u32);
            if self.flash.read(offset, &mut buf).is_err() {
                continue;
            }

            // 0xFF는 미사용 슬롯
            if buf[0] == 0xFF {
                continue;
            }

            if buf[0] != MAGIC_BYTE {
                continue;
            }

            let counter = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
            let mut key = [0u8; 32];
            key.copy_from_slice(&buf[5..37]);

            if best_counter.map_or(true, |c| counter >= c) {
                best_counter = Some(counter);
                best_key = Some(key);
            }
        }

        best_key
    }

    pub fn load_peer_mac(&mut self) -> Option<[u8; 6]> {
        let (slot_count, _) = self.slot_info();
        let mut best_counter: Option<u32> = None;
        let mut best_mac: Option<[u8; 6]> = None;

        for idx in 0..slot_count {
            let mut buf = [0u8; SLOT_SIZE];
            let offset = self.nvs_offset + (idx as u32 * SLOT_SIZE as u32);
            if self.flash.read(offset, &mut buf).is_err() {
                continue;
            }

            if buf[0] == 0xFF {
                continue;
            }

            if buf[0] != MAGIC_MAC {
                continue;
            }

            let counter = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&buf[5..11]);

            if best_counter.map_or(true, |c| counter >= c) {
                best_counter = Some(counter);
                best_mac = Some(mac);
            }
        }

        best_mac
    }

    pub fn save_key(&mut self, key: &[u8; 32]) -> Result<(), ()> {
        let (slot_count, base) = self.slot_info();

        // 저장 위치를 찾는다: 비어있는 슬롯 우선, 없으면 가장 오래된 슬롯 갱신
        let mut best_idx: Option<usize> = None;
        let mut best_counter: Option<u32> = None;
        let mut first_empty: Option<usize> = None;

        for idx in 0..slot_count {
            let mut buf = [0u8; SLOT_SIZE];
            let offset = base + (idx as u32 * SLOT_SIZE as u32);
            self.flash.read(offset, &mut buf).map_err(|_| ())?;

            if buf[0] == 0xFF {
                if first_empty.is_none() {
                    first_empty = Some(idx);
                }
                continue;
            }

            if buf[0] != MAGIC_BYTE {
                continue;
            }

            let counter = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
            if best_counter.map_or(true, |c| counter >= c) {
                best_counter = Some(counter);
                best_idx = Some(idx);
            }
        }

        let next_idx = if let Some(empty) = first_empty {
            empty
        } else {
            let next = best_idx.map(|i| i + 1).unwrap_or(0);
            if next >= slot_count {
                // 슬롯이 모두 채워져 있으면 전체 파티션을 지우고 첫 슬롯부터 다시 사용
                self.erase_partition()?;
                0
            } else {
                next
            }
        };

        let counter = best_counter.unwrap_or(0).wrapping_add(1);

        let mut buf = [0u8; SLOT_SIZE];
        buf[0] = MAGIC_BYTE;
        buf[1..5].copy_from_slice(&counter.to_le_bytes());
        buf[5..37].copy_from_slice(key);

        let write_offset = base + (next_idx as u32 * SLOT_SIZE as u32);
        self.flash.write(write_offset, &buf).map_err(|_| ())
    }

    pub fn save_peer_mac(&mut self, mac: &[u8; 6]) -> Result<(), ()> {
        let (slot_count, base) = self.slot_info();

        // MAC 저장도 동일 정책(빈 슬롯 우선, 이후 순환 + 롤오버)으로 관리한다.
        let mut best_idx: Option<usize> = None;
        let mut best_counter: Option<u32> = None;
        let mut first_empty: Option<usize> = None;

        for idx in 0..slot_count {
            let mut buf = [0u8; SLOT_SIZE];
            let offset = base + (idx as u32 * SLOT_SIZE as u32);
            self.flash.read(offset, &mut buf).map_err(|_| ())?;

            if buf[0] == 0xFF {
                if first_empty.is_none() {
                    first_empty = Some(idx);
                }
                continue;
            }

            if buf[0] != MAGIC_MAC {
                continue;
            }

            let counter = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
            if best_counter.map_or(true, |c| counter >= c) {
                best_counter = Some(counter);
                best_idx = Some(idx);
            }
        }

        let next_idx = if let Some(empty) = first_empty {
            empty
        } else {
            let next = best_idx.map(|i| i + 1).unwrap_or(0);
            if next >= slot_count {
                self.erase_partition()?;
                0
            } else {
                next
            }
        };

        let counter = best_counter.unwrap_or(0).wrapping_add(1);

        let mut buf = [0u8; SLOT_SIZE];
        buf[0] = MAGIC_MAC;
        buf[1..5].copy_from_slice(&counter.to_le_bytes());
        buf[5..11].copy_from_slice(mac);

        let write_offset = base + (next_idx as u32 * SLOT_SIZE as u32);
        self.flash.write(write_offset, &buf).map_err(|_| ())
    }

    fn slot_info(&self) -> (usize, u32) {
        let slot_count = (self.nvs_size as usize) / SLOT_SIZE;
        (slot_count.max(1), self.nvs_offset)
    }

    fn erase_partition(&mut self) -> Result<(), ()> {
        // 저장소 전체를 초기화해서 슬롯을 재사용 가능한 상태로 만든다.
        self.flash
            .erase(self.nvs_offset, self.nvs_offset + self.nvs_size)
            .map_err(|_| ())
    }
}
