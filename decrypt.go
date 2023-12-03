package gohwdecrypt

func DecryptBuffer(hwd_keyset *HwdKeyset, buffer []byte) {
	mul1 := hwd_keyset.Key1
	mul2 := hwd_keyset.Key2
	mul_static := hwd_keyset.Key3
	var k1, k2, k3 uint32

	for i := range buffer {
		k1 = mul1 >> 0x18 // eax
		k2 = mul2 >> 0x18 // ebp
		k3 = mul_static >> 0x18
		buffer[i] ^= byte(k1 ^ k2 ^ k3)
		mul1 *= 0x343FD
		mul1 += 0x269EC3

		mul2 *= 0x343FD
		mul2 += 0x269EC3

		mul_static *= 0x343FD
		mul_static += 0x269EC3
	}
	*hwd_keyset = HwdKeyset{
		Key1: mul1,
		Key2: mul2,
		Key3: mul_static,
	}
}
