# A DHT implementation for Dagger

This DHT implementation is aiming to provide a DHT for Dagger with the following properties
* flexible transport usage with
  * fast UDP based operation
  * fallback to TCP-based operation (maybe though libp2p)
  * support operation on top of libp2p
* flexible message encoding that plays well with the above transports
* provide node lookup, content storage/lookup, and provider storage/lookup operations
  * roughly follow the libp2p-dht specifications from https://github.com/libp2p/specs/tree/master/kad-dht
  * provide compatibility mode with the above specs

Current implementation is based on a stripped down version on nim-eth's Discovery v4 implementation. Base files were copied
from nim-eth@26ab9b078e610b0eb685e8d98a1f34d9bfabb053
