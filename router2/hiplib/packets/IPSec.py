#!/usr/bin/python

# Copyright (C) 2019 strangebit

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# https://tools.ietf.org/html/rfc7402
# https://tools.ietf.org/html/rfc4303
# https://tools.ietf.org/html/rfc4302

import logging

IPSEC_TRANSPORT_FORMAT      = 0x0FFF;

# Protocol numbers
IPSEC_ESP_PROTOCOL          = 0x32;  # ESP protocol (original)
IPSEC_AH_PROTOCOL           = 0x33;  # AH protocol (new)
IPSEC_PROTOCOL              = 0x33;  # Using AH instead of ESP

# Common IPSec header fields
IPSEC_SPI_LENGTH            = 0x4;
IPSEC_SEQUENCE_LENGTH       = 0x4;

IPSEC_SPI_OFFSET            = 0x0;
IPSEC_SEQUENCE_OFFSET       = 0x4;

# AH specific constants
AH_NEXT_HEADER_OFFSET       = 0x0;
AH_PAYLOAD_LENGTH_OFFSET    = 0x1;
AH_RESERVED_OFFSET          = 0x2;
AH_SPI_OFFSET               = 0x4;
AH_SEQUENCE_OFFSET          = 0x8;
AH_ICV_OFFSET               = 0xC;

AH_NEXT_HEADER_LENGTH       = 0x1;
AH_PAYLOAD_LENGTH_LENGTH    = 0x1;
AH_RESERVED_LENGTH          = 0x2;
AH_FIXED_HEADER_LENGTH      = 0xC;  # Next Header + Payload Length + Reserved + SPI + Sequence

# Legacy ESP constants (kept for compatibility)
IPSEC_PAYLOAD_OFFSET        = 0x8;
IPSEC_IV_LENGTH             = 0x10;

class AHPacket():
	"""
	Authentication Header (AH) packet implementation according to RFC 4302
	AH provides authentication and integrity but no confidentiality
	"""
	def __init__(self, buffer = None, next_header = 0x61):  # 0x61 = IPv6 (common for tunneled traffic)
		if not buffer:
			# Initialize with AH fixed header
			self.buffer = bytearray([0] * AH_FIXED_HEADER_LENGTH)
			self.set_next_header(next_header)
			self.set_payload_length(1)  # Length in 4-byte words minus 2 (minimum for AH)
			# Reserved field is already zero-initialized
		else:
			# Ensure buffer is a bytearray for proper manipulation
			self.buffer = bytearray(buffer) if not isinstance(buffer, bytearray) else buffer

	def set_next_header(self, next_header):
		"""Set the Next Header field (protocol of the payload)"""
		self.buffer[AH_NEXT_HEADER_OFFSET] = next_header & 0xFF

	def get_next_header(self):
		"""Get the Next Header field"""
		return self.buffer[AH_NEXT_HEADER_OFFSET]

	def set_payload_length(self, length):
		"""Set the Payload Length field (in 4-byte words minus 2)"""
		self.buffer[AH_PAYLOAD_LENGTH_OFFSET] = length & 0xFF

	def get_payload_length(self):
		"""Get the Payload Length field"""
		return self.buffer[AH_PAYLOAD_LENGTH_OFFSET]

	def set_spi(self, spi):
		"""Set the Security Parameters Index"""
		self.buffer[AH_SPI_OFFSET] = (spi >> 24) & 0xFF
		self.buffer[AH_SPI_OFFSET + 1] = (spi >> 16) & 0xFF
		self.buffer[AH_SPI_OFFSET + 2] = (spi >> 8) & 0xFF
		self.buffer[AH_SPI_OFFSET + 3] = (spi & 0xFF)

	def get_spi(self):
		"""Get the Security Parameters Index"""
		return ((self.buffer[AH_SPI_OFFSET] << 24) |
			(self.buffer[AH_SPI_OFFSET + 1] << 16) |
			(self.buffer[AH_SPI_OFFSET + 2] << 8)  |
			self.buffer[AH_SPI_OFFSET + 3])

	def set_sequence(self, sequence):
		"""Set the Sequence Number"""
		self.buffer[AH_SEQUENCE_OFFSET] = (sequence >> 24) & 0xFF
		self.buffer[AH_SEQUENCE_OFFSET + 1] = (sequence >> 16) & 0xFF
		self.buffer[AH_SEQUENCE_OFFSET + 2] = (sequence >> 8) & 0xFF
		self.buffer[AH_SEQUENCE_OFFSET + 3] = (sequence & 0xFF)

	def get_sequence(self):
		"""Get the Sequence Number"""
		return ((self.buffer[AH_SEQUENCE_OFFSET] << 24) |
			(self.buffer[AH_SEQUENCE_OFFSET + 1] << 16) |
			(self.buffer[AH_SEQUENCE_OFFSET + 2] << 8)  |
			self.buffer[AH_SEQUENCE_OFFSET + 3])

	def add_icv(self, icv):
		"""Add the Integrity Check Value (ICV) - HMAC"""
		# Insert ICV at the correct position (after fixed header, before payload)
		icv_start = AH_FIXED_HEADER_LENGTH
		payload = self.buffer[icv_start:]  # Save existing payload
		self.buffer = self.buffer[:icv_start]  # Keep only fixed header
		self.buffer += icv  # Add ICV
		self.buffer += payload  # Add payload back

		# Update payload length to include ICV
		total_ah_length = AH_FIXED_HEADER_LENGTH + len(icv)
		ah_length_words = (total_ah_length + 3) // 4 - 2  # Convert to 4-byte words minus 2
		self.set_payload_length(ah_length_words)

	def add_payload(self, payload):
		"""Add the protected payload (unencrypted for AH)"""
		self.buffer += payload

	def get_payload(self):
		"""Get the payload starting after the AH header + ICV"""
		ah_total_length = (self.get_payload_length() + 2) * 4
		return self.buffer[ah_total_length:]

	def get_icv(self):
		"""Get the Integrity Check Value"""
		icv_length = (self.get_payload_length() + 2) * 4 - AH_FIXED_HEADER_LENGTH
		return self.buffer[AH_ICV_OFFSET:AH_ICV_OFFSET + icv_length]

	def get_byte_buffer(self):
		"""Get the complete packet buffer"""
		return self.buffer

	def get_auth_data(self):
		"""Get data for authentication (AH header with ICV field zeroed + payload)"""
		# For authentication, we need the AH header with ICV field set to zero
		# Create a copy of the buffer
		auth_buffer = bytearray(self.buffer)

		# Calculate ICV length
		icv_length = (self.get_payload_length() + 2) * 4 - AH_FIXED_HEADER_LENGTH

		# Zero out the ICV field for authentication calculation
		for i in range(icv_length):
			if AH_ICV_OFFSET + i < len(auth_buffer):
				auth_buffer[AH_ICV_OFFSET + i] = 0

		return auth_buffer


# Legacy ESP packet class (kept for compatibility during transition)
class IPSecPacket():
	def __init__(self, buffer = None):
		if not buffer:
			self.buffer = bytearray([0] * (IPSEC_SPI_LENGTH + IPSEC_SEQUENCE_LENGTH))
		else:
			self.buffer = buffer
	def add_payload(self, payload):
		self.buffer += payload;
	def get_payload(self):
		return self.buffer[IPSEC_PAYLOAD_OFFSET:];
	def set_spi(self, spi):
		self.buffer[IPSEC_SPI_OFFSET] = (spi >> 24) & 0xFF;
		self.buffer[IPSEC_SPI_OFFSET + 1] = (spi >> 16) & 0xFF;
		self.buffer[IPSEC_SPI_OFFSET + 2] = (spi >> 8) & 0xFF;
		self.buffer[IPSEC_SPI_OFFSET + 3] = (spi & 0xFF);
	def get_spi(self):
		return ((self.buffer[IPSEC_SPI_OFFSET] << 24) |
			(self.buffer[IPSEC_SPI_OFFSET + 1] << 16) |
			(self.buffer[IPSEC_SPI_OFFSET + 2] << 8)  |
			self.buffer[IPSEC_SPI_OFFSET + 3]);
	def set_sequence(self, sequence):
		self.buffer[IPSEC_SEQUENCE_OFFSET] = (sequence >> 24) & 0xFF;
		self.buffer[IPSEC_SEQUENCE_OFFSET + 1] = (sequence >> 16) & 0xFF;
		self.buffer[IPSEC_SEQUENCE_OFFSET + 2] = (sequence >> 8) & 0xFF;
		self.buffer[IPSEC_SEQUENCE_OFFSET + 3] = (sequence & 0xFF);
	def get_sequence(self):
		return ((self.buffer[IPSEC_SEQUENCE_OFFSET] << 24) |
			(self.buffer[IPSEC_SEQUENCE_OFFSET + 1] << 16) |
			(self.buffer[IPSEC_SEQUENCE_OFFSET + 2] << 8)  |
			self.buffer[IPSEC_SEQUENCE_OFFSET + 3]);
	def get_byte_buffer(self):
		return self.buffer;


class AHUtils():
	"""
	Utility functions for AH packet processing
	"""
	@staticmethod
	def calculate_ah_length(icv_length):
		"""Calculate AH payload length field value"""
		# AH length = (total AH length in 4-byte words) - 2
		total_length = AH_FIXED_HEADER_LENGTH + icv_length
		return (total_length + 3) // 4 - 2  # Round up to 4-byte words, then subtract 2

	@staticmethod
	def get_icv_length_from_ah_length(ah_length):
		"""Get ICV length from AH payload length field"""
		total_length = (ah_length + 2) * 4
		return total_length - AH_FIXED_HEADER_LENGTH


class IPSecUtils():
	"""
	Legacy ESP utility functions (kept for compatibility)
	"""
	@staticmethod
	def pad(block_size, data, next_header):
		pad_length = block_size - ((len(data) + 2) % block_size) & 0xFF;
		padding = bytearray([i for i in range(1, pad_length + 1)]);
		return data + padding + bytearray([pad_length, next_header]);

	@staticmethod
	def get_next_header(data):
		return data[len(data) - 1];

	@staticmethod
	def unpad(block_size, data):
		pad_length = (data[len(data) - 2]) & 0xFF;
		return data[:len(data) - pad_length - 2];
