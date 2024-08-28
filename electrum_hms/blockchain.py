# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@ecdsa.org
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import os
import sqlite3
import threading
import time
import traceback
import algomodule
from typing import Optional, Dict, Mapping, Sequence, TYPE_CHECKING, Union

from . import util
from .bitcoin import hash_encode
from .crypto import sha256d
from . import constants
from .util import bfh
from .logging import get_logger, Logger

if TYPE_CHECKING:
    from .simple_config import SimpleConfig

_logger = get_logger(__name__)

HEADER_SIZE = 80  # bytes
V7_HEADER_SIZE = 112
V8_HEADER_SIZE = 144

MAX_TARGET = 0x00000FFFFF000000000000000000000000000000000000000000000000000000
POW_TARGET_SPACING = int(1 * 60)  # PIVX: 1 minute
DGW_PAST_BLOCKS = 24

class MissingHeader(Exception):
    pass

class InvalidHeader(Exception):
    pass

def serialize_header(header_dict: dict) -> bytes:
    s = (
        int.to_bytes(header_dict['version'], length=4, byteorder="little", signed=False)
        + bfh(header_dict['prev_block_hash'])[::-1]
        + bfh(header_dict['merkle_root'])[::-1]
        + int.to_bytes(int(header_dict['timestamp']), length=4, byteorder="little", signed=False)
        + int.to_bytes(int(header_dict['bits']), length=4, byteorder="little", signed=False)
        + int.to_bytes(int(header_dict['nonce']), length=4, byteorder="little", signed=False)
    )
   
    if header_dict['version'] > 3:
        s += bfh(header_dict['accumulator_checkpoint'])[::-1]
    return s


def deserialize_header(s: bytes, height: int) -> dict:
    if not s:
        raise InvalidHeader('Invalid header: {}'.format(s))
    if len(s) < HEADER_SIZE:
        raise InvalidHeader('Invalid header length: {}'.format(len(s)))
    h = {}
    h['version'] = int.from_bytes(s[0:4], byteorder='little')
    h['prev_block_hash'] = hash_encode(s[4:36])
    h['merkle_root'] = hash_encode(s[36:68])
    h['timestamp'] = int.from_bytes(s[68:72], byteorder='little')
    h['bits'] = int.from_bytes(s[72:76], byteorder='little')
    h['nonce'] = int.from_bytes(s[76:80], byteorder='little')
    
    if h['version'] > 3:
        h['accumulator_checkpoint'] = hash_encode(s[80:112])

    h['block_height'] = height
    return h

def hash_header(header: dict) -> str:
    if header is None:
        return '0' * 64
    if header.get('prev_block_hash') is None:
        header['prev_block_hash'] = '00'*32
    return hash_raw_header(serialize_header(header))

def hash_raw_header(header: bytes) -> str:
    assert isinstance(header, bytes)
    if header[0] > 3:
        return hash_encode(sha256d(header))
    return hash_encode(PoWHash(header))

def PoWHash(x):
    x = util.to_bytes(x, 'utf8')
    out = bytes(algomodule._quark_hash(x))
    return out
pow_hash_header = hash_header


# key: blockhash hex at forkpoint
# the chain at some key is the best chain that includes the given hash
blockchains = {}  # type: Dict[str, Blockchain]
blockchains_lock = threading.RLock()  # lock order: take this last; so after Blockchain.lock


def read_blockchains(config: 'SimpleConfig'):
    best_chain = Blockchain(config=config,
                            forkpoint=0,
                            parent=None,
                            forkpoint_hash=constants.net.GENESIS,
                            prev_hash=None)
    blockchains[constants.net.GENESIS] = best_chain

    # forks
    fdir = os.path.join(util.get_headers_dir(config), 'forks')
    util.make_dir(fdir)
    # files are named as: fork2_{forkpoint}_{prev_hash}_{first_hash}
    l = filter(lambda x: x.startswith('fork2_') and '.' not in x and len(x.split('_')) == 4, os.listdir(fdir))
    l = sorted(l, key=lambda x: int(x.split('_')[1]))  # sort by forkpoint

    def delete_chain(filename, reason):
        _logger.info(f"[blockchain] deleting chain {filename}: {reason}")
        path = os.path.join(fdir, filename)
        try:
            os.unlink(path)
        except BaseException as e:
            _logger.error(f"failed delete {path} {e}")

    def instantiate_chain(filename):
        __, forkpoint, prev_hash, first_hash = filename.split('_')
        forkpoint = int(forkpoint)
        prev_hash = (64-len(prev_hash)) * "0" + prev_hash  # left-pad with zeroes
        first_hash = (64-len(first_hash)) * "0" + first_hash
        # forks below the max checkpoint are not allowed
        if forkpoint <= constants.net.max_checkpoint():
            delete_chain(filename, "deleting fork below max checkpoint")
            return
        # find parent (sorting by forkpoint guarantees it's already instantiated)
        for parent in blockchains.values():
            if parent.check_hash(forkpoint - 1, prev_hash):
                break
        else:
            delete_chain(filename, "cannot find parent for chain")
            return
        b = Blockchain(config=config,
                       forkpoint=forkpoint,
                       parent=parent,
                       forkpoint_hash=first_hash,
                       prev_hash=prev_hash)
        # consistency checks
        h = b.read_header(b.forkpoint)
        if first_hash != hash_header(h) or not b.parent.can_connect(h, check_height=False):
            if b.conn:
                b.conn.close()
            delete_chain(filename, "invalid fork")
            return
        chain_id = b.get_id()
        assert first_hash == chain_id, (first_hash, chain_id)
        blockchains[chain_id] = b

    for filename in l:
        instantiate_chain(filename)

def get_best_chain() -> 'Blockchain':
    return blockchains[constants.net.GENESIS]

# block hash -> chain work; up to and including that block
_CHAINWORK_CACHE = {
    "0000000000000000000000000000000000000000000000000000000000000000": 0,  # virtual block at height -1
}  # type: Dict[str, int]

class Blockchain(Logger):
    """
    Manages blockchain headers and their verification
    """

    def __init__(self, config: 'SimpleConfig', forkpoint: int, parent: Optional['Blockchain'],
                 forkpoint_hash: str, prev_hash: Optional[str]):
        assert isinstance(forkpoint_hash, str) and len(forkpoint_hash) == 64, forkpoint_hash
        assert (prev_hash is None) or (isinstance(prev_hash, str) and len(prev_hash) == 64), prev_hash
        # assert (parent is None) == (forkpoint == 0)
        if 0 < forkpoint <= constants.net.max_checkpoint():
            raise Exception(f"cannot fork below max checkpoint. forkpoint: {forkpoint}")
        Logger.__init__(self)
        self.config = config
        self.forkpoint = forkpoint  # height of first header
        self.parent = parent
        self._forkpoint_hash = forkpoint_hash  # blockhash at forkpoint. "first hash"
        self._prev_hash = prev_hash  # blockhash immediately before forkpoint
        self.lock = threading.RLock()
        self.swaping = threading.Event()
        self.conn = None
        self.init_db()
        self.update_size()

    def with_lock(func):
        def func_wrapper(self, *args, **kwargs):
            with self.lock:
                return func(self, *args, **kwargs)
        return func_wrapper

    def init_db(self):
        self.conn = sqlite3.connect(self.path(), check_same_thread=False)
        cursor = self.conn.cursor()
        try:
            cursor.execute('CREATE TABLE IF NOT EXISTS header '
                           '(height INT PRIMARY KEY NOT NULL, data BLOB NOT NULL)')
            self.conn.commit()
        except (sqlite3.DatabaseError, ) as e:
            self.logger.info(f"error when init_db', {e}, 'will delete the db file and recreate")
            os.remove(self.path())
            self.conn = None
            self.init_db()
        finally:
            cursor.close()

    @with_lock
    def is_valid(self):
        conn = sqlite3.connect(self.path(), check_same_thread=False)
        cursor = conn.cursor()
        cursor.execute('SELECT min(height), max(height) FROM header')
        min_height, max_height = cursor.fetchone()
        max_height = max_height or 0
        min_height = min_height or 0
        cursor.execute('SELECT COUNT(*) FROM header')
        size = int(cursor.fetchone()[0])
        cursor.close()
        conn.close()
        if not min_height == self.forkpoint:
            return False
        if size > 0 and not size == max_height - min_height + 1:
            return False
        return True
    
    @property
    def checkpoints(self):
        return constants.net.CHECKPOINTS

    def get_max_child(self) -> Optional[int]:
        children = self.get_direct_children()
        return max([x.forkpoint for x in children]) if children else None

    def get_max_forkpoint(self) -> int:
        """Returns the max height where there is a fork
        related to this chain.
        """
        mc = self.get_max_child()
        return mc if mc is not None else self.forkpoint

    def get_direct_children(self) -> Sequence['Blockchain']:
        with blockchains_lock:
            return list(filter(lambda y: y.parent==self, blockchains.values()))

    def get_parent_heights(self) -> Mapping['Blockchain', int]:
        """Returns map: (parent chain -> height of last common block)"""
        with self.lock, blockchains_lock:
            result = {self: self.height()}
            chain = self
            while True:
                parent = chain.parent
                if parent is None: break
                result[parent] = chain.forkpoint - 1
                chain = parent
            return result

    def get_height_of_last_common_block_with_chain(self, other_chain: 'Blockchain') -> int:
        last_common_block_height = 0
        our_parents = self.get_parent_heights()
        their_parents = other_chain.get_parent_heights()
        for chain in our_parents:
            if chain in their_parents:
                h = min(our_parents[chain], their_parents[chain])
                last_common_block_height = max(last_common_block_height, h)
        return last_common_block_height

    @with_lock
    def get_branch_size(self) -> int:
        return self.height() - self.get_max_forkpoint() + 1

    def get_name(self) -> str:
        return self.get_hash(self.get_max_forkpoint()).lstrip('0')[0:10]

    def check_header(self, header: dict) -> bool:
        header_hash = hash_header(header)
        height = header.get('block_height')
        return self.check_hash(height, header_hash)

    def check_hash(self, height: int, header_hash: str) -> bool:
        """Returns whether the hash of the block at given height
        is the given hash.
        """
        assert isinstance(header_hash, str) and len(header_hash) == 64, header_hash  # hex
        try:
            return header_hash == self.get_hash(height)
        except Exception:
            return False

    def fork(parent, header: dict) -> 'Blockchain':
        if not parent.can_connect(header, check_height=False):
            raise Exception("forking header does not connect to parent chain")
        forkpoint = header.get('block_height')
        self = Blockchain(config=parent.config,
                          forkpoint=forkpoint,
                          parent=parent,
                          forkpoint_hash=hash_header(header),
                          prev_hash=parent.get_hash(forkpoint-1))
        self.logger.info(f'[fork] {forkpoint}, {parent.forkpoint}')
        self.assert_headers_file_available(parent.path())
        # open(self.path(), 'w+').close()
        self.save_header(header)
        # put into global dict. note that in some cases
        # save_header might have already put it there but that's OK
        chain_id = self.get_id()
        with blockchains_lock:
            blockchains[chain_id] = self
        return self

    @with_lock
    def height(self) -> int:
        return self.forkpoint + self.size() - 1

    @with_lock
    def size(self) -> int:
        return self._size

    @with_lock
    def update_size(self) -> None:
        conn = sqlite3.connect(self.path(), check_same_thread=False)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM header')
        count = int(cursor.fetchone()[0])
        self._size = count
        cursor.close()

    @classmethod
    def verify_header(cls, header: dict, prev_hash: str, target: int, expected_header_hash: str=None) -> None:
        _hash = hash_header(header)
        if expected_header_hash and expected_header_hash != _hash:
            raise InvalidHeader("hash mismatches with expected: {} vs {}".format(expected_header_hash, _hash))
        if prev_hash != header.get('prev_block_hash'):
            raise InvalidHeader("prev hash mismatch: %s vs %s" % (prev_hash, header.get('prev_block_hash')))
        if constants.net.TESTNET:
            return
        return
        bits = cls.target_to_bits(target)
        if bits != header.get('bits'):
            raise InvalidHeader("bits mismatch: %s vs %s" % (bits, header.get('bits')))
        _pow_hash = pow_hash_header(header)
        pow_hash_as_num = int.from_bytes(bfh(_pow_hash), byteorder='big')
        if pow_hash_as_num > target:
            raise InvalidHeader(f"insufficient proof of work: {pow_hash_as_num} vs target {target}")

    def verify_chunk(self, index: int, data: list) -> None:
        num = len(data)
        start_height = index * 2016
        prev_hash = self.get_hash(start_height - 1)
        target = self.get_target(index-1)
        for i in range(num):
            height = start_height + i
            try:
                expected_header_hash = self.get_hash(height)
            except MissingHeader:
                expected_header_hash = None
            raw_header = bfh(data[i])
            header = deserialize_header(raw_header, index*2016 + i)
            self.verify_header(header, prev_hash, target, expected_header_hash)
            prev_hash = hash_header(header)

    @with_lock
    def path(self):
        d = util.get_headers_dir(self.config)
        if self.parent is None:
            filename = 'blockchain_headers'
        else:
            assert self.forkpoint > 0, self.forkpoint
            prev_hash = self._prev_hash.lstrip('0')
            first_hash = self._forkpoint_hash.lstrip('0')
            basename = f'fork2_{self.forkpoint}_{prev_hash}_{first_hash}'
            filename = os.path.join('forks', basename)
        return os.path.join(d, filename)

    @with_lock
    def save_chunk(self, index: int, raw_headers: list):
        self.logger.info(f'{self.forkpoint} try to save chunk {(index * 2016)}')
        assert index >= 0, index

        if self.swaping.is_set():
            return
        try:
            conn = self.conn
            cursor = self.conn.cursor()
        except (sqlite3.ProgrammingError, AttributeError):
            conn = sqlite3.connect(self.path(), check_same_thread=False)
            cursor = conn.cursor()

        forkpoint = self.forkpoint
        if forkpoint is None:
            forkpoint = 0
        headers = [(index * 2016 + i, v)
                   for i, v in enumerate(raw_headers)
                   if index * 2016 + i >= forkpoint]

        cursor.executemany('REPLACE INTO header (height, data) VALUES(?,?)', headers)
        cursor.close()
        conn.commit()
        self.update_size()
        self.swap_with_parent()

    def swap_with_parent(self) -> None:
        if self.parent is None:
            return
        with self.lock, blockchains_lock:
            parent = self.parent

            self.update_size()
            parent.update_size()
            parent_branch_size = parent.height() - self.forkpoint + 1
            if parent_branch_size >= self._size:
                return

            if self.swaping.is_set() or parent.swaping.is_set():
                return
            self.swaping.set()
            parent.swaping.set()

            parent_id = parent.get_id()
            forkpoint = self.forkpoint

            global blockchains
            try:
                self.logger.info(f'swap, {forkpoint}, {parent_id}')
                for i in range(forkpoint, forkpoint + self._size):
                    # print_error('swaping', i)
                    header = self.read_header(i, deserialize=False)
                    parent_header = parent.read_header(i, deserialize=False)
                    parent.write(header, i)
                    if parent_header:
                        self.write(parent_header, i)
                    else:
                        self.delete(i)
            except (BaseException,) as e:
                import traceback, sys
                traceback.print_exc(file=sys.stderr)
                self.logger.error(f'swap error, {e}')
            # update size
            self.update_size()
            parent.update_size()
            self.swaping.clear()
            parent.swaping.clear()
            self.logger.info('swap finished')
            parent.swap_with_parent()

    def get_id(self) -> str:
        return self._forkpoint_hash

    def assert_headers_file_available(self, path):
        if os.path.exists(path):
            return
        elif not os.path.exists(util.get_headers_dir(self.config)):
            raise FileNotFoundError('Electrum headers_dir does not exist. Was it deleted while running?')
        else:
            raise FileNotFoundError('Cannot find headers file but headers_dir is there. Should be at {}'.format(path))

    def write(self, raw_header: bytes, height: int):
        if self.forkpoint > 0 and height < self.forkpoint:
            return
        if not raw_header:
            if height:
                self.delete(height)
            else:
                self.delete_all()
            return
        with self.lock:
            self.logger.info(f'{self.path()} {self.forkpoint} try to write {height}')
            if height > self._size + self.forkpoint:
                return
            try:
                conn = self.conn
                cursor = self.conn.cursor()
            except (sqlite3.ProgrammingError, AttributeError):
                conn = sqlite3.connect(self.path(), check_same_thread=False)
                cursor = conn.cursor()
            cursor.execute('REPLACE INTO header (height, data) VALUES(?,?)', (height, raw_header))
            cursor.close()
            conn.commit()
            self.update_size()

    def delete(self, height: int):
        self.logger.info(f'{self.forkpoint} try to delete {height}')
        if self.forkpoint > 0 and height < self.forkpoint:
            return
        with self.lock:
            self.logger.info(f'{self.forkpoint} try to delete {height}')
            try:
                conn = self.conn
                cursor = conn.cursor()
            except (sqlite3.ProgrammingError, AttributeError):
                conn = sqlite3.connect(self.path(), check_same_thread=False)
                cursor = conn.cursor()
            cursor.execute('DELETE FROM header where height=?', (height,))
            cursor.close()
            conn.commit()
            self.update_size()

    def delete_all(self):
        if self.swaping.is_set():
            return
        with self.lock:
            try:
                conn = self.conn
                cursor = self.conn.cursor()
            except (sqlite3.ProgrammingError, AttributeError):
                conn = sqlite3.connect(self.path(), check_same_thread=False)
                cursor = conn.cursor()
            cursor.execute('DELETE FROM header')
            cursor.close()
            conn.commit()
            self._size = 0

    @with_lock
    def save_header(self, header: dict) -> None:
        data = serialize_header(header)
        self.write(data, header.get('block_height'))
        self.swap_with_parent()

    @with_lock
    def read_header(self, height: int, deserialize=True) -> Union[dict, bytes]:
        if height < 0:
            return
        if height < self.forkpoint:
            return self.parent.read_header(height)
        if height > self.height():
            return

        try:
            conn = sqlite3.connect(self.path(), check_same_thread=False)
            cursor = conn.cursor()
            cursor.execute('SELECT data FROM header WHERE height=?', (height,))
            result = cursor.fetchone()
            cursor.close()
            conn.close()
        except BaseException as e:
            self.logger.error(f'read_header error:{e}')
            return

        if not result or len(result) < 1:
            self.logger.error(f'read_header {height}, {self.forkpoint}, {self.parent.get_id()}, {result}, {self.height()}')
            self.update_size()
            return
        header = result[0]
        if deserialize:
            if type(header) == str:
                header = bfh(header)
            return deserialize_header(header, height)
        return header

    def header_at_tip(self) -> Optional[dict]:
        """Return latest header."""
        height = self.height()
        return self.read_header(height)

    def is_tip_stale(self) -> bool:
        STALE_DELAY = 8 * 60 * 60  # in seconds
        header = self.header_at_tip()
        if not header:
            return True
        # note: We check the timestamp only in the latest header.
        #       The Bitcoin consensus has a lot of leeway here:
        #       - needs to be greater than the median of the timestamps of the past 11 blocks, and
        #       - up to at most 2 hours into the future compared to local clock
        #       so there is ~2 hours of leeway in either direction
        if header['timestamp'] + STALE_DELAY < time.time():
            return True
        return False

    def get_hash(self, height: int) -> str:
        if height == -1:
            return '0000000000000000000000000000000000000000000000000000000000000000'
        elif height == 0:
            return constants.net.GENESIS
        elif str(height) in self.checkpoints:
            return self.checkpoints[str(height)]
        else:
            header = self.read_header(height)
            if header is None:
                raise MissingHeader(height)
            return hash_header(header)

    def get_target(self, index: int) -> int:
        # compute target from chunk x, used in chunk x+1
        if constants.net.TESTNET:
            return 0
        if index == -1:
            return MAX_TARGET
        if index < len(self.checkpoints):
            h, t = self.checkpoints[index]
            return t
        # new target
        first = self.read_header(index * 2016)
        last = self.read_header(index * 2016 + 2015)
        if not first or not last:
            raise MissingHeader()
        bits = last.get('bits')
        target = self.bits_to_target(bits)
        nActualTimespan = last.get('timestamp') - first.get('timestamp')
        nTargetTimespan = 14 * 24 * 60 * 60
        nActualTimespan = max(nActualTimespan, nTargetTimespan // 4)
        nActualTimespan = min(nActualTimespan, nTargetTimespan * 4)
        new_target = min(MAX_TARGET, (target * nActualTimespan) // nTargetTimespan)
        # not any target can be represented in 32 bits:
        new_target = self.bits_to_target(self.target_to_bits(new_target))
        return new_target

    @classmethod
    def bits_to_target(cls, bits: int) -> int:
        # arith_uint256::SetCompact in Bitcoin Core
        if not (0 <= bits < (1 << 32)):
            raise InvalidHeader(f"bits should be uint32. got {bits!r}")
        bitsN = (bits >> 24) & 0xff
        bitsBase = bits & 0x7fffff
        if bitsN <= 3:
            target = bitsBase >> (8 * (3-bitsN))
        else:
            target = bitsBase << (8 * (bitsN-3))
        if target != 0 and bits & 0x800000 != 0:
            # Bit number 24 (0x800000) represents the sign of N
            raise InvalidHeader("target cannot be negative")
        if (target != 0 and
                (bitsN > 34 or
                 (bitsN > 33 and bitsBase > 0xff) or
                 (bitsN > 32 and bitsBase > 0xffff))):
            raise InvalidHeader("target has overflown")
        return target

    @classmethod
    def target_to_bits(cls, target: int) -> int:
        # arith_uint256::GetCompact in Bitcoin Core
        # see https://github.com/bitcoin/bitcoin/blob/7fcf53f7b4524572d1d0c9a5fdc388e87eb02416/src/arith_uint256.cpp#L223
        c = target.to_bytes(length=32, byteorder='big')
        bitsN = len(c)
        while bitsN > 0 and c[0] == 0:
            c = c[1:]
            bitsN -= 1
            if len(c) < 3:
                c += b'\x00'
        bitsBase = int.from_bytes(c[:3], byteorder='big')
        if bitsBase >= 0x800000:
            bitsN += 1
            bitsBase >>= 8
        return bitsN << 24 | bitsBase

    def chainwork_of_header_at_height(self, height: int) -> int:
        """work done by single header at given height"""
        chunk_idx = height // 2016 - 1
        target = self.get_target(chunk_idx)
        work = ((2 ** 256 - target - 1) // (target + 1)) + 1
        return work

    @with_lock
    def get_chainwork(self, height=None) -> int:
        if height is None:
            height = max(0, self.height())
        return height

    def can_connect(self, header: dict, check_height: bool=True) -> bool:
        if header is None:
            return False
        height = header['block_height']
        if check_height and self.height() != height - 1:
            return False
        if height == 0:
            return hash_header(header) == constants.net.GENESIS
        try:
            prev_hash = self.get_hash(height - 1)
        except Exception:
            return False
        if prev_hash != header.get('prev_block_hash'):
            return False
        try:
            target = self.get_target(height // 2016 - 1)
        except MissingHeader:
            return False
        try:
            self.verify_header(header, prev_hash, target)
        except BaseException as e:
            return False
        return True

    def connect_chunk(self, idx: int, data: list) -> bool:
        assert idx >= 0, idx
        try:
            self.verify_chunk(idx, data)
        except BaseException as e:
            self.logger.info(f'verify_chunk idx {idx} failed: {repr(e)}')
            print(traceback.format_exc())
            return False

        try:
            self.save_chunk(idx, data)
            return True
        except BaseException as e:
            self.logger.info(f'save_chunk idx {idx} failed: {repr(e)}')
            print(traceback.format_exc())
            return False
    
    def get_checkpoints(self):
        # for each chunk, store the hash of the last block and the target after the chunk
        cp = []
        n = self.height() // 2016
        for index in range(n):
            h = self.get_hash((index+1) * 2016 -1)
            target = self.get_target(index)
            cp.append((h, target))
        return cp


def check_header(header: dict) -> Optional[Blockchain]:
    """Returns any Blockchain that contains header, or None."""
    if type(header) is not dict:
        return None
    with blockchains_lock: chains = list(blockchains.values())
    for b in chains:
        if b.check_header(header):
            return b
    return None


def can_connect(header: dict) -> Optional[Blockchain]:
    """Returns the Blockchain that has a tip that directly links up
    with header, or None.
    """
    with blockchains_lock: chains = list(blockchains.values())
    for b in chains:
        if b.can_connect(header):
            return b
    return None


def get_chains_that_contain_header(height: int, header_hash: str) -> Sequence[Blockchain]:
    """Returns a list of Blockchains that contain header, best chain first."""
    with blockchains_lock: chains = list(blockchains.values())
    chains = [chain for chain in chains
              if chain.check_hash(height=height, header_hash=header_hash)]
    chains = sorted(chains, key=lambda x: x.get_chainwork(), reverse=True)
    return chains
