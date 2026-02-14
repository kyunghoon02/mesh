use embedded_storage::{ReadStorage, Storage};
use esp_partition_table::PartitionTable;
use esp_storage::FlashStorage;

const MAGIC_MAC: u8 = 0xB1;
const SLOT_SIZE: usize = 64; // 헤더 5B + MAC 6B + 여유 공간

pub struct PairingStorage {
    flash: Option<FlashStorage>,
    partition_offset: u32,
    partition_size: u32,
}

impl PairingStorage {
    /// flash 파티션을 탐색해 mesh_pairing 또는 mesh_key 슬롯 영역을 찾는다.
    pub fn new() -> Self {
        let mut flash = FlashStorage::new();
        let mut table_bin = [0u8; 3072];

        if flash.read(0x8000, &mut table_bin).is_err() {
            return Self {
                flash: None,
                partition_offset: 0,
                partition_size: 0,
            };
        }

        let mut found = None;
        for part in PartitionTable::iter(&table_bin).filter_map(|p| p.ok()) {
            if part.name() == "mesh_pairing" || part.name() == "mesh_key" {
                found = Some(part);
                break;
            }
        }

        match found {
            Some(part) => Self {
                flash: Some(flash),
                partition_offset: part.offset(),
                partition_size: part.size(),
            },
            None => Self {
                flash: None,
                partition_offset: 0,
                partition_size: 0,
            },
        }
    }

    /// 저장된 peer MAC 중 최신 카운터 항목을 읽어 반환한다.
    pub fn load_peer_mac(&mut self) -> Option<[u8; 6]> {
        if !self.is_available() {
            return None;
        }

        let (slot_count, base) = self.slot_info();
        let mut last_counter: Option<u32> = None;
        let mut result: Option<[u8; 6]> = None;

        for idx in 0..slot_count {
            let mut buf = [0u8; SLOT_SIZE];
            let offset = base + (idx as u32 * SLOT_SIZE as u32);
            if let Err(_) = self.flash.as_mut()?.read(offset, &mut buf) {
                continue;
            }

            if buf[0] == 0xFF || buf[0] != MAGIC_MAC {
                continue;
            }

            let counter = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&buf[5..11]);

            if last_counter.is_none_or(|prev| counter >= prev) {
                last_counter = Some(counter);
                result = Some(mac);
            }
        }

        result
    }

    /// peer MAC을 최신 슬롯에 저장한다. 슬롯이 가득 차면 초기화 후 재사용한다.
    pub fn save_peer_mac(&mut self, mac: &[u8; 6]) -> Result<(), ()> {
        if !self.is_available() {
            return Err(());
        }

        let (slot_count, base) = self.slot_info();
        let mut found_empty: Option<usize> = None;
        let mut found_latest: Option<usize> = None;
        let mut latest_counter: Option<u32> = None;

        for idx in 0..slot_count {
            let mut buf = [0u8; SLOT_SIZE];
            let offset = base + (idx as u32 * SLOT_SIZE as u32);
            self.flash
                .as_mut()
                .ok_or(())?
                .read(offset, &mut buf)
                .map_err(|_| ())?;

            if buf[0] == 0xFF {
                if found_empty.is_none() {
                    found_empty = Some(idx);
                }
                continue;
            }

            if buf[0] != MAGIC_MAC {
                continue;
            }

            let counter = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
            if latest_counter.map_or(true, |v| counter >= v) {
                latest_counter = Some(counter);
                found_latest = Some(idx);
            }
        }

        let write_index = if let Some(empty) = found_empty {
            empty
        } else {
            match found_latest {
                Some(last) if last + 1 < slot_count => last + 1,
                Some(_) => {
                    self.erase_partition()?;
                    0
                }
                None => 0,
            }
        };

        let next_counter = latest_counter.unwrap_or(0).wrapping_add(1);
        let mut buf = [0u8; SLOT_SIZE];
        buf[0] = MAGIC_MAC;
        buf[1..5].copy_from_slice(&next_counter.to_le_bytes());
        buf[5..11].copy_from_slice(mac);

        let write_offset = base + (write_index as u32 * SLOT_SIZE as u32);
        self.flash
            .as_mut()
            .ok_or(())?
            .write(write_offset, &buf)
            .map_err(|_| ())
    }

    fn is_available(&self) -> bool {
        self.flash.is_some() && self.partition_size > 0
    }

    fn slot_info(&self) -> (usize, u32) {
        if self.partition_size == 0 {
            return (0, self.partition_offset);
        }
        let slots = (self.partition_size as usize) / SLOT_SIZE;
        (slots.max(1), self.partition_offset)
    }

    fn erase_partition(&mut self) -> Result<(), ()> {
        self.flash
            .as_mut()
            .ok_or(())?
            .erase(
                self.partition_offset,
                self.partition_offset + self.partition_size,
            )
            .map_err(|_| ())
    }
}
