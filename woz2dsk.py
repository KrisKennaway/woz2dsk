import sys
from typing import Dict, Optional, Tuple

import wozardry

DEFAULT_ADDRESS_PROLOGUE = bytes.fromhex("D5 AA 96")
DEFAULT_ADDRESS_EPILOGUE = bytes.fromhex("DE AA EB")
DEFAULT_DATA_PROLOGUE = bytes.fromhex("D5 AA AD")
DEFAULT_DATA_EPILOGUE = bytes.fromhex("DE AA EB")


class DiskException(Exception):
    pass


class TrackMismatch(DiskException):
    def __init__(self, track_found: int, track_expected: int, sector: int):
        self.track_found = track_found
        self.track_expected = track_expected
        self.sector = sector

    def __str__(self):
        return ("Track mismatch for track %02x (!= %02x) sector %02x" %
                (self.track_found, self.track_expected, self.sector))


class AddressChecksumMismatch(DiskException):
    def __init__(self, track: int, sector: int):
        self.track = track
        self.sector = sector

    def __str__(self):
        return ("Address checksum mismatch for track %02x sector %02x" %
                (self.track, self.sector))


class AddressEpilogueNotFound(DiskException):
    def __init__(self, track: int, sector: int):
        self.track = track
        self.sector = sector

    def __str__(self):
        return ("Address epilogue field not found for track %02x sector %02x" %
                (self.track, self.sector))


class DataChecksumMismatch(DiskException):
    def __init__(self, track: int, sector: int):
        self.track = track
        self.sector = sector

    def __str__(self):
        return ("Data checksum mismatch for track %02x sector %02x" %
                (self.track, self.sector))


class DataSyncBytesNotFound(DiskException):
    def __init__(self, track: int, sector: int):
        self.track = track
        self.sector = sector

    def __str__(self):
        return ("Data sync bytes not found for track %02x sector %02x" %
                (self.track, self.sector))


class DataPrologueNotFound(DiskException):
    def __init__(self, track: int, sector: int):
        self.track = track
        self.sector = sector

    def __str__(self):
        return ("Data prologue field not found for track %02x sector %02x" %
                (self.track, self.sector))


class DataEpilogueNotFound(DiskException):
    def __init__(self, track: int, sector: int):
        self.track = track
        self.sector = sector

    def __str__(self):
        return ("Data epilogue field not found for track %02x sector %02x" %
                (self.track, self.sector))


def decode_44(xx: int, yy: int) -> int:
    return ((xx & 0b01010101) << 1) + (yy & 0b01010101)


# Maps 6-bit data to 6,2-encoded nibble
ENCODE_62 = [0x96, 0x97, 0x9a, 0x9b, 0x9d, 0x9e, 0x9f, 0xa6, 0xa7,
             0xab, 0xac, 0xad, 0xae, 0xaf, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6,
             0xb7, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xcb,
             0xcd, 0xce, 0xcf, 0xd3, 0xd6, 0xd7, 0xd9, 0xda, 0xdb,
             0xdc, 0xdd, 0xde, 0xdf, 0xe5, 0xe6, 0xe7, 0xe9, 0xea,
             0xeb, 0xec, 0xed, 0xee, 0xef, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6,
             0xf7, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff]

# Maps 6,2-encoded nibble to 6-bit data
DECODE_62_MAP = dict((v, k) for k, v in enumerate(ENCODE_62))


def swap_bits(bits):
    return ((bits & 0b1) << 1) ^ ((bits & 0b10) >> 1)


def decode_62(data: bytearray) -> Tuple[bytearray, int]:
    assert len(data) == 342, len(data)
    output = bytearray(256)

    running_checksum = 0x00
    for idx, bits6 in enumerate(data[:86]):
        running_checksum ^= DECODE_62_MAP[bits6]

        low2 = (running_checksum >> 0) & 0b11
        output[idx] ^= swap_bits(low2)

        mid2 = (running_checksum >> 2) & 0b11
        output[idx + 86] ^= swap_bits(mid2)

        if idx < 84:
            hi2 = (running_checksum >> 4) & 0b11
            output[idx + 86 * 2] ^= swap_bits(hi2)

    for idx, bits6 in enumerate(data[86:]):
        running_checksum ^= DECODE_62_MAP[bits6]
        output[idx] ^= running_checksum << 2

    return output, running_checksum


class Sector:
    DOS_33_ORDER = [0x0, 0xd, 0xb, 0x9, 0x7, 0x5, 0x3, 0x1, 0xe, 0xc, 0xa, 0x8,
                    0x6, 0x4, 0x2, 0xf]

    def __init__(self, data: Optional[bytearray] = None):
        if data and len(data) != 256:
            raise ValueError("Sector data is %d bytes != 256" % len(data))
        self.data = data or bytearray(256)


class Track:
    def __init__(self, track_num: int, track: wozardry.Track,
                 address_prologue: bytes = None,
                 address_epilogue: bytes = None,
                 data_prologue: bytes = None,
                 data_epilogue: bytes = None):
        self.track = track
        self.track_num = track_num

        self.address_prologue = address_prologue or DEFAULT_ADDRESS_PROLOGUE
        self.address_epilogue = address_epilogue or DEFAULT_ADDRESS_EPILOGUE
        self.data_prologue = data_prologue or DEFAULT_DATA_PROLOGUE
        self.data_epilogue = data_epilogue or DEFAULT_DATA_EPILOGUE

    def find_within(self, sequence, num_nibbles: int) -> bool:
        seen = [0] * len(sequence)
        cnt = 0
        while cnt < num_nibbles:
            del seen[0]
            seen.append(next(self.track.nibble()))
            if tuple(seen) == tuple(sequence):
                return True
            cnt += 1
        return False

    def sectors(self) -> Dict[int, Sector]:
        sectors = {}
        while True:
            self.track.find(self.address_prologue)
            volume = decode_44(next(self.track.nibble()),
                               next(self.track.nibble()))
            track_num = decode_44(next(self.track.nibble()),
                                  next(self.track.nibble()))
            sector_num = decode_44(next(self.track.nibble()),
                                   next(self.track.nibble()))
            if self.track_num != track_num:
                raise TrackMismatch(track_num, self.track_num, sector_num)

            if sector_num in sectors:
                return sectors

            checksum = decode_44(next(self.track.nibble()),
                                 next(self.track.nibble()))
            expected_checksum = volume ^ self.track_num ^ sector_num
            if checksum != expected_checksum:
                raise AddressChecksumMismatch(self.track_num, sector_num)

            if not self.find_within(self.address_epilogue[:2], 2):
                raise AddressEpilogueNotFound(self.track_num, sector_num)
            # Skip last epilogue nibble since it's often not written completely
            _ = next(self.track.nibble())

            # Find next sync byte
            if not self.find_within(bytes([0xff]), 20):
                raise DataSyncBytesNotFound(self.track_num, sector_num)

            if not self.find_within(self.data_prologue, 20):
                raise DataPrologueNotFound(self.track_num, sector_num)

            nibbles = bytearray()
            for _ in range(342):
                nibbles.append(next(self.track.nibble()))
            decoded, checksum = decode_62(nibbles)

            expected_checksum = DECODE_62_MAP[next(self.track.nibble())]
            if checksum != expected_checksum:
                raise DataChecksumMismatch(self.track_num, sector_num)

            if not self.find_within(self.data_epilogue[:2], 2):
                raise DataEpilogueNotFound(self.track_num, sector_num)
            # Skip last epilogue nibble since it's often not written completely
            _ = next(self.track.nibble())

            sectors[sector_num] = Sector(decoded)


class Disk:
    def __init__(self, woz_image, address_prologue: bytes = None,
                 address_epilogue: bytes = None,
                 data_prologue: bytes = None,
                 data_epilogue: bytes = None):
        self.woz_image = woz_image
        self.address_prologue = address_prologue or DEFAULT_ADDRESS_PROLOGUE
        self.address_epilogue = address_epilogue or DEFAULT_ADDRESS_EPILOGUE
        self.data_prologue = data_prologue or DEFAULT_DATA_PROLOGUE
        self.data_epilogue = data_epilogue or DEFAULT_DATA_EPILOGUE

    def seek(self, track_num) -> Track:
        return Track(track_num, self.woz_image.seek(track_num),
                     self.address_prologue, self.address_epilogue,
                     self.data_prologue, self.data_epilogue)


def main(argv):
    if len(argv) != 3:
        raise ValueError("woz2dsk.py <file.woz> <output.dsk>")

    with open(argv[1], "rb") as fp:
        woz_image = wozardry.WozDiskImage(fp)

    disk = Disk(woz_image)
    expected_sectors = set(range(16))
    with open(argv[2], "wb") as fp:
        for track_num in range(35):
            track = disk.seek(track_num)
            sectors = track.sectors()
            if set(sectors.keys()) != expected_sectors:
                print(
                    "Track %d: Sectors missing: %s" % (track_num, sorted(list(
                        expected_sectors - set(sectors.keys())))))

            for sector_num in Sector.DOS_33_ORDER:
                sector = sectors.get(sector_num, Sector())
                fp.write(sector.data)


if __name__ == "__main__":
    main(sys.argv)
