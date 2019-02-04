import hashlib
import struct

def round_to_multiple(number, size):
  """Rounds a number up to nearest multiple of another number.
  Args:
    number: The number to round up.
    size: The multiple to round up to.
  Returns:
    If |number| is a multiple of |size|, returns |number|, otherwise
    returns |number| + |size|.
  """
  remainder = number % size
  if remainder == 0:
    return number
  return number + size - remainder


def round_to_pow2(number):
  """Rounds a number up to the next power of 2.
  Args:
    number: The number to round up.
  Returns:
    If |number| is already a power of 2 then |number| is
    returned. Otherwise the smallest power of 2 greater than |number|
    is returned.
  """
  return 2**((number - 1).bit_length())

class AvbVBMetaHeader(object):
  """A class for parsing and writing AVB vbmeta images.
  Attributes:
    The attributes correspond to the |AvbVBMetaHeader| struct
    defined in avb_vbmeta_header.h.
  """

  SIZE = 256

  # Keep in sync with |reserved0| and |reserved| field of
  # |AvbVBMetaImageHeader|.
  RESERVED0 = 4
  RESERVED = 80

  # Keep in sync with |AvbVBMetaImageHeader|.
  FORMAT_STRING = ('!4s2L'  # magic, 2 x version
                   '2Q'  # 2 x block size
                   'L'  # algorithm type
                   '2Q'  # offset, size (hash)
                   '2Q'  # offset, size (signature)
                   '2Q'  # offset, size (public key)
                   '2Q'  # offset, size (public key metadata)
                   '2Q'  # offset, size (descriptors)
                   'Q'  # rollback_index
                   'L' +  # flags
                   str(RESERVED0) + 'x' +  # padding for reserved bytes
                   '47sx' +  # NUL-terminated release string
                   str(RESERVED) + 'x')  # padding for reserved bytes

  def __init__(self, data=None):
    assert struct.calcsize(self.FORMAT_STRING) == self.SIZE

    if data:
      (self.magic, self.required_libavb_version_major,
       self.required_libavb_version_minor,
       self.authentication_data_block_size, self.auxiliary_data_block_size,
       self.algorithm_type, self.hash_offset, self.hash_size,
       self.signature_offset, self.signature_size, self.public_key_offset,
       self.public_key_size, self.public_key_metadata_offset,
       self.public_key_metadata_size, self.descriptors_offset,
       self.descriptors_size,
       self.rollback_index,
       self.flags,
       self.release_string) = struct.unpack(self.FORMAT_STRING, data)


class AvbDescriptor(object):
  """Class for AVB descriptor.
  See the |AvbDescriptor| C struct for more information.
  Attributes:
    tag: The tag identifying what kind of descriptor this is.
    data: The data in the descriptor.
  """

  SIZE = 16
  FORMAT_STRING = ('!QQ')  # tag, num_bytes_following (descriptor header)

  def __init__(self, data):
    """Initializes a new property descriptor.
    Arguments:
      data: If not None, must be a bytearray().
    Raises:
      LookupError: If the given descriptor is malformed.
    """
    assert struct.calcsize(self.FORMAT_STRING) == self.SIZE

    if data:
      (self.tag, num_bytes_following) = (
          struct.unpack(self.FORMAT_STRING, data[0:self.SIZE]))
      self.data = data[self.SIZE:self.SIZE + num_bytes_following]
    else:
      self.tag = None
      self.data = None


class AvbPropertyDescriptor(AvbDescriptor):
  """A class for property descriptors.
  See the |AvbPropertyDescriptor| C struct for more information.
  Attributes:
    key: The key.
    value: The key.
  """

  TAG = 0
  SIZE = 32
  FORMAT_STRING = ('!QQ'  # tag, num_bytes_following (descriptor header)
                   'Q'  # key size (bytes)
                   'Q')  # value size (bytes)

  def __init__(self, data=None):
    """Initializes a new property descriptor.
    Arguments:
      data: If not None, must be a bytearray of size |SIZE|.
    Raises:
      LookupError: If the given descriptor is malformed.
    """
    AvbDescriptor.__init__(self, None)
    assert struct.calcsize(self.FORMAT_STRING) == self.SIZE

    if data:
      (tag, num_bytes_following, key_size,
       value_size) = struct.unpack(self.FORMAT_STRING, data[0:self.SIZE])
      expected_size = round_to_multiple(
          self.SIZE - 16 + key_size + 1 + value_size + 1, 8)
      if tag != self.TAG or num_bytes_following != expected_size:
        raise LookupError('Given data does not look like a property '
                          'descriptor.')
      self.key = data[self.SIZE:(self.SIZE + key_size)]
      self.value = data[(self.SIZE + key_size + 1):(self.SIZE + key_size + 1 +
                                                    value_size)]
    else:
      self.key = ''
      self.value = ''

class AvbHashtreeDescriptor(AvbDescriptor):
  """A class for hashtree descriptors.
  See the |AvbHashtreeDescriptor| C struct for more information.
  Attributes:
    dm_verity_version: dm-verity version used.
    image_size: Size of the image, after rounding up to |block_size|.
    tree_offset: Offset of the hash tree in the file.
    tree_size: Size of the tree.
    data_block_size: Data block size
    hash_block_size: Hash block size
    fec_num_roots: Number of roots used for FEC (0 if FEC is not used).
    fec_offset: Offset of FEC data (0 if FEC is not used).
    fec_size: Size of FEC data (0 if FEC is not used).
    hash_algorithm: Hash algorithm used.
    partition_name: Partition name.
    salt: Salt used.
    root_digest: Root digest.
  """

  TAG = 1
  RESERVED = 64
  SIZE = 116 + RESERVED
  FORMAT_STRING = ('!QQ'  # tag, num_bytes_following (descriptor header)
                   'L'  # dm-verity version used
                   'Q'  # image size (bytes)
                   'Q'  # tree offset (bytes)
                   'Q'  # tree size (bytes)
                   'L'  # data block size (bytes)
                   'L'  # hash block size (bytes)
                   'L'  # FEC number of roots
                   'Q'  # FEC offset (bytes)
                   'Q'  # FEC size (bytes)
                   '32s'  # hash algorithm used
                   'L'  # partition name (bytes)
                   'L'  # salt length (bytes)
                   'L' +  # root digest length (bytes)
                   str(RESERVED) + 's')  # reserved

  def __init__(self, data=None):
    """Initializes a new hashtree descriptor.
    Arguments:
      data: If not None, must be a bytearray of size |SIZE|.
    Raises:
      LookupError: If the given descriptor is malformed.
    """
    AvbDescriptor.__init__(self, None)
    assert struct.calcsize(self.FORMAT_STRING) == self.SIZE

    if data:
      (tag, num_bytes_following, self.dm_verity_version, self.image_size,
       self.tree_offset, self.tree_size, self.data_block_size,
       self.hash_block_size, self.fec_num_roots, self.fec_offset, self.fec_size,
       self.hash_algorithm, partition_name_len, salt_len,
       root_digest_len, _) = struct.unpack(self.FORMAT_STRING,
                                           data[0:self.SIZE])
      expected_size = round_to_multiple(
          self.SIZE - 16 + partition_name_len + salt_len + root_digest_len, 8)
      if tag != self.TAG or num_bytes_following != expected_size:
        raise LookupError('Given data does not look like a hashtree '
                          'descriptor.')
      # Nuke NUL-bytes at the end.
      self.hash_algorithm = self.hash_algorithm.split('\0', 1)[0]
      o = 0
      self.partition_name = str(data[(self.SIZE + o):(self.SIZE + o +
                                                      partition_name_len)])
      # Validate UTF-8 - decode() raises UnicodeDecodeError if not valid UTF-8.
      self.partition_name.decode('utf-8')
      o += partition_name_len
      self.salt = data[(self.SIZE + o):(self.SIZE + o + salt_len)]
      o += salt_len
      self.root_digest = data[(self.SIZE + o):(self.SIZE + o + root_digest_len)]
      if root_digest_len != len(hashlib.new(name=self.hash_algorithm).digest()):
        raise LookupError('root_digest_len doesn\'t match hash algorithm')

class AvbHashDescriptor(AvbDescriptor):
  """A class for hash descriptors.
  See the |AvbHashDescriptor| C struct for more information.
  Attributes:
    image_size: Image size, in bytes.
    hash_algorithm: Hash algorithm used.
    partition_name: Partition name.
    salt: Salt used.
    digest: The hash value of salt and data combined.
  """

  TAG = 2
  RESERVED = 64
  SIZE = 68 + RESERVED
  FORMAT_STRING = ('!QQ'  # tag, num_bytes_following (descriptor header)
                   'Q'  # image size (bytes)
                   '32s'  # hash algorithm used
                   'L'  # partition name (bytes)
                   'L'  # salt length (bytes)
                   'L' +  # digest length (bytes)
                   str(RESERVED) + 's')  # reserved

  def __init__(self, data=None):
    """Initializes a new hash descriptor.
    Arguments:
      data: If not None, must be a bytearray of size |SIZE|.
    Raises:
      LookupError: If the given descriptor is malformed.
    """
    AvbDescriptor.__init__(self, None)
    assert struct.calcsize(self.FORMAT_STRING) == self.SIZE

    if data:
      (tag, num_bytes_following, self.image_size, self.hash_algorithm,
       partition_name_len, salt_len,
       digest_len, _) = struct.unpack(self.FORMAT_STRING, data[0:self.SIZE])
      expected_size = round_to_multiple(
          self.SIZE - 16 + partition_name_len + salt_len + digest_len, 8)
      if tag != self.TAG or num_bytes_following != expected_size:
        raise LookupError('Given data does not look like a hash ' 'descriptor.')
      # Nuke NUL-bytes at the end.
      self.hash_algorithm = self.hash_algorithm.split(b'\0', 1)[0]
      self.hash_algorithm = self.hash_algorithm.decode('UTF-8')
      o = 0
      self.partition_name = data[(self.SIZE + o):(self.SIZE + o +  partition_name_len)]
      # Validate UTF-8 - decode() raises UnicodeDecodeError if not valid UTF-8.
      self.partition_name=self.partition_name.decode('utf-8')
      o += partition_name_len
      self.salt = data[(self.SIZE + o):(self.SIZE + o + salt_len)]
      o += salt_len
      self.digest = data[(self.SIZE + o):(self.SIZE + o + digest_len)]
      if digest_len != len(hashlib.new(name=self.hash_algorithm).digest()):
        raise LookupError('digest_len doesn\'t match hash algorithm')

def calc_hash_level_offsets(image_size, block_size, digest_size):
  """Calculate the offsets of all the hash-levels in a Merkle-tree.
  Arguments:
    image_size: The size of the image to calculate a Merkle-tree for.
    block_size: The block size, e.g. 4096.
    digest_size: The size of each hash, e.g. 32 for SHA-256.
  Returns:
    A tuple where the first argument is an array of offsets and the
    second is size of the tree, in bytes.
  """
  level_offsets = []
  level_sizes = []
  tree_size = 0

  num_levels = 0
  size = image_size
  while size > block_size:
    num_blocks = (size + block_size - 1) / block_size
    level_size = round_to_multiple(num_blocks * digest_size, block_size)

    level_sizes.append(level_size)
    tree_size += level_size
    num_levels += 1

    size = level_size

  for n in range(0, num_levels):
    offset = 0
    for m in range(n + 1, num_levels):
      offset += level_sizes[m]
    level_offsets.append(int(offset))

  return level_offsets, int(tree_size)

def generate_hash_tree(image, image_size, block_size, hash_alg_name, salt,
                       digest_padding, hash_level_offsets, tree_size):
  """Generates a Merkle-tree for a file.
  Args:
    image: The image, as a file.
    image_size: The size of the image.
    block_size: The block size, e.g. 4096.
    hash_alg_name: The hash algorithm, e.g. 'sha256' or 'sha1'.
    salt: The salt to use.
    digest_padding: The padding for each digest.
    hash_level_offsets: The offsets from calc_hash_level_offsets().
    tree_size: The size of the tree, in number of bytes.
  Returns:
    A tuple where the first element is the top-level hash and the
    second element is the hash-tree.
  """
  hash_ret = bytearray(tree_size)
  hash_src_offset = 0
  hash_src_size = image_size
  level_num = 0
  while hash_src_size > block_size:
    level_output = b''
    remaining = hash_src_size
    while remaining > 0:
      hasher = hashlib.new(name=hash_alg_name, string=salt)
      # Only read from the file for the first level - for subsequent
      # levels, access the array we're building.
      if level_num == 0:
        image.seek(hash_src_offset + hash_src_size - remaining)
        data = image.read(min(remaining, block_size))
      else:
        offset = hash_level_offsets[level_num - 1] + hash_src_size - remaining
        data = hash_ret[offset:offset + block_size]
      hasher.update(data)

      remaining -= len(data)
      if len(data) < block_size:
        hasher.update(b'\0' * (block_size - len(data)))
      level_output += hasher.digest()
      if digest_padding > 0:
        level_output += b'\0' * digest_padding

    padding_needed = (round_to_multiple(
        len(level_output), block_size) - len(level_output))
    level_output += b'\0' * padding_needed

    # Copy level-output into resulting tree.
    offset = hash_level_offsets[level_num]
    hash_ret[offset:offset + len(level_output)] = level_output

    # Continue on to the next level.
    hash_src_size = len(level_output)
    level_num += 1

  hasher = hashlib.new(name=hash_alg_name, string=salt)
  hasher.update(level_output)
  return hasher.digest(), hash_ret