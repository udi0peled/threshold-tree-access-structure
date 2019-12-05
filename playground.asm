
./playground:     file format elf64-x86-64


Disassembly of section .init:

0000000000001428 <_init>:
    1428:	48 83 ec 08          	sub    rsp,0x8
    142c:	48 8b 05 a5 8b 20 00 	mov    rax,QWORD PTR [rip+0x208ba5]        # 209fd8 <__gmon_start__>
    1433:	48 85 c0             	test   rax,rax
    1436:	74 02                	je     143a <_init+0x12>
    1438:	ff d0                	call   rax
    143a:	48 83 c4 08          	add    rsp,0x8
    143e:	c3                   	ret    

Disassembly of section .plt:

0000000000001440 <.plt>:
    1440:	ff 35 92 89 20 00    	push   QWORD PTR [rip+0x208992]        # 209dd8 <_GLOBAL_OFFSET_TABLE_+0x8>
    1446:	ff 25 94 89 20 00    	jmp    QWORD PTR [rip+0x208994]        # 209de0 <_GLOBAL_OFFSET_TABLE_+0x10>
    144c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

0000000000001450 <BN_div@plt>:
    1450:	ff 25 92 89 20 00    	jmp    QWORD PTR [rip+0x208992]        # 209de8 <BN_div@OPENSSL_1_1_0>
    1456:	68 00 00 00 00       	push   0x0
    145b:	e9 e0 ff ff ff       	jmp    1440 <.plt>

0000000000001460 <printf@plt>:
    1460:	ff 25 8a 89 20 00    	jmp    QWORD PTR [rip+0x20898a]        # 209df0 <printf@GLIBC_2.2.5>
    1466:	68 01 00 00 00       	push   0x1
    146b:	e9 d0 ff ff ff       	jmp    1440 <.plt>

0000000000001470 <BN_nnmod@plt>:
    1470:	ff 25 82 89 20 00    	jmp    QWORD PTR [rip+0x208982]        # 209df8 <BN_nnmod@OPENSSL_1_1_0>
    1476:	68 02 00 00 00       	push   0x2
    147b:	e9 c0 ff ff ff       	jmp    1440 <.plt>

0000000000001480 <BN_set_flags@plt>:
    1480:	ff 25 7a 89 20 00    	jmp    QWORD PTR [rip+0x20897a]        # 209e00 <BN_set_flags@OPENSSL_1_1_0>
    1486:	68 03 00 00 00       	push   0x3
    148b:	e9 b0 ff ff ff       	jmp    1440 <.plt>

0000000000001490 <memset@plt>:
    1490:	ff 25 72 89 20 00    	jmp    QWORD PTR [rip+0x208972]        # 209e08 <memset@GLIBC_2.2.5>
    1496:	68 04 00 00 00       	push   0x4
    149b:	e9 a0 ff ff ff       	jmp    1440 <.plt>

00000000000014a0 <ERR_get_error@plt>:
    14a0:	ff 25 6a 89 20 00    	jmp    QWORD PTR [rip+0x20896a]        # 209e10 <ERR_get_error@OPENSSL_1_1_0>
    14a6:	68 05 00 00 00       	push   0x5
    14ab:	e9 90 ff ff ff       	jmp    1440 <.plt>

00000000000014b0 <BN_bn2binpad@plt>:
    14b0:	ff 25 62 89 20 00    	jmp    QWORD PTR [rip+0x208962]        # 209e18 <BN_bn2binpad@OPENSSL_1_1_0>
    14b6:	68 06 00 00 00       	push   0x6
    14bb:	e9 80 ff ff ff       	jmp    1440 <.plt>

00000000000014c0 <BN_mod_mul@plt>:
    14c0:	ff 25 5a 89 20 00    	jmp    QWORD PTR [rip+0x20895a]        # 209e20 <BN_mod_mul@OPENSSL_1_1_0>
    14c6:	68 07 00 00 00       	push   0x7
    14cb:	e9 70 ff ff ff       	jmp    1440 <.plt>

00000000000014d0 <BN_CTX_free@plt>:
    14d0:	ff 25 52 89 20 00    	jmp    QWORD PTR [rip+0x208952]        # 209e28 <BN_CTX_free@OPENSSL_1_1_0>
    14d6:	68 08 00 00 00       	push   0x8
    14db:	e9 60 ff ff ff       	jmp    1440 <.plt>

00000000000014e0 <BN_mod_inverse@plt>:
    14e0:	ff 25 4a 89 20 00    	jmp    QWORD PTR [rip+0x20894a]        # 209e30 <BN_mod_inverse@OPENSSL_1_1_0>
    14e6:	68 09 00 00 00       	push   0x9
    14eb:	e9 50 ff ff ff       	jmp    1440 <.plt>

00000000000014f0 <BN_is_zero@plt>:
    14f0:	ff 25 42 89 20 00    	jmp    QWORD PTR [rip+0x208942]        # 209e38 <BN_is_zero@OPENSSL_1_1_0>
    14f6:	68 0a 00 00 00       	push   0xa
    14fb:	e9 40 ff ff ff       	jmp    1440 <.plt>

0000000000001500 <BN_mul_word@plt>:
    1500:	ff 25 3a 89 20 00    	jmp    QWORD PTR [rip+0x20893a]        # 209e40 <BN_mul_word@OPENSSL_1_1_0>
    1506:	68 0b 00 00 00       	push   0xb
    150b:	e9 30 ff ff ff       	jmp    1440 <.plt>

0000000000001510 <puts@plt>:
    1510:	ff 25 32 89 20 00    	jmp    QWORD PTR [rip+0x208932]        # 209e48 <puts@GLIBC_2.2.5>
    1516:	68 0c 00 00 00       	push   0xc
    151b:	e9 20 ff ff ff       	jmp    1440 <.plt>

0000000000001520 <__assert_fail@plt>:
    1520:	ff 25 2a 89 20 00    	jmp    QWORD PTR [rip+0x20892a]        # 209e50 <__assert_fail@GLIBC_2.2.5>
    1526:	68 0d 00 00 00       	push   0xd
    152b:	e9 10 ff ff ff       	jmp    1440 <.plt>

0000000000001530 <EC_GROUP_new_by_curve_name@plt>:
    1530:	ff 25 22 89 20 00    	jmp    QWORD PTR [rip+0x208922]        # 209e58 <EC_GROUP_new_by_curve_name@OPENSSL_1_1_0>
    1536:	68 0e 00 00 00       	push   0xe
    153b:	e9 00 ff ff ff       	jmp    1440 <.plt>

0000000000001540 <EC_GROUP_get0_order@plt>:
    1540:	ff 25 1a 89 20 00    	jmp    QWORD PTR [rip+0x20891a]        # 209e60 <EC_GROUP_get0_order@OPENSSL_1_1_0>
    1546:	68 0f 00 00 00       	push   0xf
    154b:	e9 f0 fe ff ff       	jmp    1440 <.plt>

0000000000001550 <putchar@plt>:
    1550:	ff 25 12 89 20 00    	jmp    QWORD PTR [rip+0x208912]        # 209e68 <putchar@GLIBC_2.2.5>
    1556:	68 10 00 00 00       	push   0x10
    155b:	e9 e0 fe ff ff       	jmp    1440 <.plt>

0000000000001560 <malloc@plt>:
    1560:	ff 25 0a 89 20 00    	jmp    QWORD PTR [rip+0x20890a]        # 209e70 <malloc@GLIBC_2.2.5>
    1566:	68 11 00 00 00       	push   0x11
    156b:	e9 d0 fe ff ff       	jmp    1440 <.plt>

0000000000001570 <BN_set_word@plt>:
    1570:	ff 25 02 89 20 00    	jmp    QWORD PTR [rip+0x208902]        # 209e78 <BN_set_word@OPENSSL_1_1_0>
    1576:	68 12 00 00 00       	push   0x12
    157b:	e9 c0 fe ff ff       	jmp    1440 <.plt>

0000000000001580 <BN_bin2bn@plt>:
    1580:	ff 25 fa 88 20 00    	jmp    QWORD PTR [rip+0x2088fa]        # 209e80 <BN_bin2bn@OPENSSL_1_1_0>
    1586:	68 13 00 00 00       	push   0x13
    158b:	e9 b0 fe ff ff       	jmp    1440 <.plt>

0000000000001590 <EC_GROUP_free@plt>:
    1590:	ff 25 f2 88 20 00    	jmp    QWORD PTR [rip+0x2088f2]        # 209e88 <EC_GROUP_free@OPENSSL_1_1_0>
    1596:	68 14 00 00 00       	push   0x14
    159b:	e9 a0 fe ff ff       	jmp    1440 <.plt>

00000000000015a0 <EC_POINT_new@plt>:
    15a0:	ff 25 ea 88 20 00    	jmp    QWORD PTR [rip+0x2088ea]        # 209e90 <EC_POINT_new@OPENSSL_1_1_0>
    15a6:	68 15 00 00 00       	push   0x15
    15ab:	e9 90 fe ff ff       	jmp    1440 <.plt>

00000000000015b0 <BN_copy@plt>:
    15b0:	ff 25 e2 88 20 00    	jmp    QWORD PTR [rip+0x2088e2]        # 209e98 <BN_copy@OPENSSL_1_1_0>
    15b6:	68 16 00 00 00       	push   0x16
    15bb:	e9 80 fe ff ff       	jmp    1440 <.plt>

00000000000015c0 <BN_num_bits@plt>:
    15c0:	ff 25 da 88 20 00    	jmp    QWORD PTR [rip+0x2088da]        # 209ea0 <BN_num_bits@OPENSSL_1_1_0>
    15c6:	68 17 00 00 00       	push   0x17
    15cb:	e9 70 fe ff ff       	jmp    1440 <.plt>

00000000000015d0 <BN_mod_sub@plt>:
    15d0:	ff 25 d2 88 20 00    	jmp    QWORD PTR [rip+0x2088d2]        # 209ea8 <BN_mod_sub@OPENSSL_1_1_0>
    15d6:	68 18 00 00 00       	push   0x18
    15db:	e9 60 fe ff ff       	jmp    1440 <.plt>

00000000000015e0 <BN_is_negative@plt>:
    15e0:	ff 25 ca 88 20 00    	jmp    QWORD PTR [rip+0x2088ca]        # 209eb0 <BN_is_negative@OPENSSL_1_1_0>
    15e6:	68 19 00 00 00       	push   0x19
    15eb:	e9 50 fe ff ff       	jmp    1440 <.plt>

00000000000015f0 <BN_sub@plt>:
    15f0:	ff 25 c2 88 20 00    	jmp    QWORD PTR [rip+0x2088c2]        # 209eb8 <BN_sub@OPENSSL_1_1_0>
    15f6:	68 1a 00 00 00       	push   0x1a
    15fb:	e9 40 fe ff ff       	jmp    1440 <.plt>

0000000000001600 <BN_rand_range@plt>:
    1600:	ff 25 ba 88 20 00    	jmp    QWORD PTR [rip+0x2088ba]        # 209ec0 <BN_rand_range@OPENSSL_1_1_0>
    1606:	68 1b 00 00 00       	push   0x1b
    160b:	e9 30 fe ff ff       	jmp    1440 <.plt>

0000000000001610 <BN_cmp@plt>:
    1610:	ff 25 b2 88 20 00    	jmp    QWORD PTR [rip+0x2088b2]        # 209ec8 <BN_cmp@OPENSSL_1_1_0>
    1616:	68 1c 00 00 00       	push   0x1c
    161b:	e9 20 fe ff ff       	jmp    1440 <.plt>

0000000000001620 <free@plt>:
    1620:	ff 25 aa 88 20 00    	jmp    QWORD PTR [rip+0x2088aa]        # 209ed0 <free@GLIBC_2.2.5>
    1626:	68 1d 00 00 00       	push   0x1d
    162b:	e9 10 fe ff ff       	jmp    1440 <.plt>

0000000000001630 <EC_POINT_point2oct@plt>:
    1630:	ff 25 a2 88 20 00    	jmp    QWORD PTR [rip+0x2088a2]        # 209ed8 <EC_POINT_point2oct@OPENSSL_1_1_0>
    1636:	68 1e 00 00 00       	push   0x1e
    163b:	e9 00 fe ff ff       	jmp    1440 <.plt>

0000000000001640 <BN_clear_free@plt>:
    1640:	ff 25 9a 88 20 00    	jmp    QWORD PTR [rip+0x20889a]        # 209ee0 <BN_clear_free@OPENSSL_1_1_0>
    1646:	68 1f 00 00 00       	push   0x1f
    164b:	e9 f0 fd ff ff       	jmp    1440 <.plt>

0000000000001650 <EC_POINT_get_affine_coordinates_GFp@plt>:
    1650:	ff 25 92 88 20 00    	jmp    QWORD PTR [rip+0x208892]        # 209ee8 <EC_POINT_get_affine_coordinates_GFp@OPENSSL_1_1_0>
    1656:	68 20 00 00 00       	push   0x20
    165b:	e9 e0 fd ff ff       	jmp    1440 <.plt>

0000000000001660 <SHA256_Final@plt>:
    1660:	ff 25 8a 88 20 00    	jmp    QWORD PTR [rip+0x20888a]        # 209ef0 <SHA256_Final@OPENSSL_1_1_0>
    1666:	68 21 00 00 00       	push   0x21
    166b:	e9 d0 fd ff ff       	jmp    1440 <.plt>

0000000000001670 <BN_clear@plt>:
    1670:	ff 25 82 88 20 00    	jmp    QWORD PTR [rip+0x208882]        # 209ef8 <BN_clear@OPENSSL_1_1_0>
    1676:	68 22 00 00 00       	push   0x22
    167b:	e9 c0 fd ff ff       	jmp    1440 <.plt>

0000000000001680 <BN_is_prime_ex@plt>:
    1680:	ff 25 7a 88 20 00    	jmp    QWORD PTR [rip+0x20887a]        # 209f00 <BN_is_prime_ex@OPENSSL_1_1_0>
    1686:	68 23 00 00 00       	push   0x23
    168b:	e9 b0 fd ff ff       	jmp    1440 <.plt>

0000000000001690 <EC_POINT_cmp@plt>:
    1690:	ff 25 72 88 20 00    	jmp    QWORD PTR [rip+0x208872]        # 209f08 <EC_POINT_cmp@OPENSSL_1_1_0>
    1696:	68 24 00 00 00       	push   0x24
    169b:	e9 a0 fd ff ff       	jmp    1440 <.plt>

00000000000016a0 <BN_zero_ex@plt>:
    16a0:	ff 25 6a 88 20 00    	jmp    QWORD PTR [rip+0x20886a]        # 209f10 <BN_zero_ex@OPENSSL_1_1_0>
    16a6:	68 25 00 00 00       	push   0x25
    16ab:	e9 90 fd ff ff       	jmp    1440 <.plt>

00000000000016b0 <atoi@plt>:
    16b0:	ff 25 62 88 20 00    	jmp    QWORD PTR [rip+0x208862]        # 209f18 <atoi@GLIBC_2.2.5>
    16b6:	68 26 00 00 00       	push   0x26
    16bb:	e9 80 fd ff ff       	jmp    1440 <.plt>

00000000000016c0 <BN_new@plt>:
    16c0:	ff 25 5a 88 20 00    	jmp    QWORD PTR [rip+0x20885a]        # 209f20 <BN_new@OPENSSL_1_1_0>
    16c6:	68 27 00 00 00       	push   0x27
    16cb:	e9 70 fd ff ff       	jmp    1440 <.plt>

00000000000016d0 <BN_CTX_new@plt>:
    16d0:	ff 25 52 88 20 00    	jmp    QWORD PTR [rip+0x208852]        # 209f28 <BN_CTX_new@OPENSSL_1_1_0>
    16d6:	68 28 00 00 00       	push   0x28
    16db:	e9 60 fd ff ff       	jmp    1440 <.plt>

00000000000016e0 <EC_POINT_mul@plt>:
    16e0:	ff 25 4a 88 20 00    	jmp    QWORD PTR [rip+0x20884a]        # 209f30 <EC_POINT_mul@OPENSSL_1_1_0>
    16e6:	68 29 00 00 00       	push   0x29
    16eb:	e9 50 fd ff ff       	jmp    1440 <.plt>

00000000000016f0 <__stack_chk_fail@plt>:
    16f0:	ff 25 42 88 20 00    	jmp    QWORD PTR [rip+0x208842]        # 209f38 <__stack_chk_fail@GLIBC_2.4>
    16f6:	68 2a 00 00 00       	push   0x2a
    16fb:	e9 40 fd ff ff       	jmp    1440 <.plt>

0000000000001700 <BN_mod_add@plt>:
    1700:	ff 25 3a 88 20 00    	jmp    QWORD PTR [rip+0x20883a]        # 209f40 <BN_mod_add@OPENSSL_1_1_0>
    1706:	68 2b 00 00 00       	push   0x2b
    170b:	e9 30 fd ff ff       	jmp    1440 <.plt>

0000000000001710 <EC_POINTs_mul@plt>:
    1710:	ff 25 32 88 20 00    	jmp    QWORD PTR [rip+0x208832]        # 209f48 <EC_POINTs_mul@OPENSSL_1_1_0>
    1716:	68 2c 00 00 00       	push   0x2c
    171b:	e9 20 fd ff ff       	jmp    1440 <.plt>

0000000000001720 <calloc@plt>:
    1720:	ff 25 2a 88 20 00    	jmp    QWORD PTR [rip+0x20882a]        # 209f50 <calloc@GLIBC_2.2.5>
    1726:	68 2d 00 00 00       	push   0x2d
    172b:	e9 10 fd ff ff       	jmp    1440 <.plt>

0000000000001730 <BN_mod_add_quick@plt>:
    1730:	ff 25 22 88 20 00    	jmp    QWORD PTR [rip+0x208822]        # 209f58 <BN_mod_add_quick@OPENSSL_1_1_0>
    1736:	68 2e 00 00 00       	push   0x2e
    173b:	e9 00 fd ff ff       	jmp    1440 <.plt>

0000000000001740 <EC_POINT_oct2point@plt>:
    1740:	ff 25 1a 88 20 00    	jmp    QWORD PTR [rip+0x20881a]        # 209f60 <EC_POINT_oct2point@OPENSSL_1_1_0>
    1746:	68 2f 00 00 00       	push   0x2f
    174b:	e9 f0 fc ff ff       	jmp    1440 <.plt>

0000000000001750 <EC_POINT_free@plt>:
    1750:	ff 25 12 88 20 00    	jmp    QWORD PTR [rip+0x208812]        # 209f68 <EC_POINT_free@OPENSSL_1_1_0>
    1756:	68 30 00 00 00       	push   0x30
    175b:	e9 e0 fc ff ff       	jmp    1440 <.plt>

0000000000001760 <RAND_bytes@plt>:
    1760:	ff 25 0a 88 20 00    	jmp    QWORD PTR [rip+0x20880a]        # 209f70 <RAND_bytes@OPENSSL_1_1_0>
    1766:	68 31 00 00 00       	push   0x31
    176b:	e9 d0 fc ff ff       	jmp    1440 <.plt>

0000000000001770 <BN_CTX_get@plt>:
    1770:	ff 25 02 88 20 00    	jmp    QWORD PTR [rip+0x208802]        # 209f78 <BN_CTX_get@OPENSSL_1_1_0>
    1776:	68 32 00 00 00       	push   0x32
    177b:	e9 c0 fc ff ff       	jmp    1440 <.plt>

0000000000001780 <BN_bn2bin@plt>:
    1780:	ff 25 fa 87 20 00    	jmp    QWORD PTR [rip+0x2087fa]        # 209f80 <BN_bn2bin@OPENSSL_1_1_0>
    1786:	68 33 00 00 00       	push   0x33
    178b:	e9 b0 fc ff ff       	jmp    1440 <.plt>

0000000000001790 <SHA256_Update@plt>:
    1790:	ff 25 f2 87 20 00    	jmp    QWORD PTR [rip+0x2087f2]        # 209f88 <SHA256_Update@OPENSSL_1_1_0>
    1796:	68 34 00 00 00       	push   0x34
    179b:	e9 a0 fc ff ff       	jmp    1440 <.plt>

00000000000017a0 <BN_rshift1@plt>:
    17a0:	ff 25 ea 87 20 00    	jmp    QWORD PTR [rip+0x2087ea]        # 209f90 <BN_rshift1@OPENSSL_1_1_0>
    17a6:	68 35 00 00 00       	push   0x35
    17ab:	e9 90 fc ff ff       	jmp    1440 <.plt>

00000000000017b0 <SHA256_Init@plt>:
    17b0:	ff 25 e2 87 20 00    	jmp    QWORD PTR [rip+0x2087e2]        # 209f98 <SHA256_Init@OPENSSL_1_1_0>
    17b6:	68 36 00 00 00       	push   0x36
    17bb:	e9 80 fc ff ff       	jmp    1440 <.plt>

00000000000017c0 <realloc@plt>:
    17c0:	ff 25 da 87 20 00    	jmp    QWORD PTR [rip+0x2087da]        # 209fa0 <realloc@GLIBC_2.2.5>
    17c6:	68 37 00 00 00       	push   0x37
    17cb:	e9 70 fc ff ff       	jmp    1440 <.plt>

00000000000017d0 <BN_CTX_end@plt>:
    17d0:	ff 25 d2 87 20 00    	jmp    QWORD PTR [rip+0x2087d2]        # 209fa8 <BN_CTX_end@OPENSSL_1_1_0>
    17d6:	68 38 00 00 00       	push   0x38
    17db:	e9 60 fc ff ff       	jmp    1440 <.plt>

00000000000017e0 <EC_POINT_add@plt>:
    17e0:	ff 25 ca 87 20 00    	jmp    QWORD PTR [rip+0x2087ca]        # 209fb0 <EC_POINT_add@OPENSSL_1_1_0>
    17e6:	68 39 00 00 00       	push   0x39
    17eb:	e9 50 fc ff ff       	jmp    1440 <.plt>

00000000000017f0 <memcpy@plt>:
    17f0:	ff 25 c2 87 20 00    	jmp    QWORD PTR [rip+0x2087c2]        # 209fb8 <memcpy@GLIBC_2.14>
    17f6:	68 3a 00 00 00       	push   0x3a
    17fb:	e9 40 fc ff ff       	jmp    1440 <.plt>

0000000000001800 <BN_CTX_start@plt>:
    1800:	ff 25 ba 87 20 00    	jmp    QWORD PTR [rip+0x2087ba]        # 209fc0 <BN_CTX_start@OPENSSL_1_1_0>
    1806:	68 3b 00 00 00       	push   0x3b
    180b:	e9 30 fc ff ff       	jmp    1440 <.plt>

0000000000001810 <CRYPTO_memcmp@plt>:
    1810:	ff 25 b2 87 20 00    	jmp    QWORD PTR [rip+0x2087b2]        # 209fc8 <CRYPTO_memcmp@OPENSSL_1_1_0>
    1816:	68 3c 00 00 00       	push   0x3c
    181b:	e9 20 fc ff ff       	jmp    1440 <.plt>

0000000000001820 <BN_free@plt>:
    1820:	ff 25 aa 87 20 00    	jmp    QWORD PTR [rip+0x2087aa]        # 209fd0 <BN_free@OPENSSL_1_1_0>
    1826:	68 3d 00 00 00       	push   0x3d
    182b:	e9 10 fc ff ff       	jmp    1440 <.plt>

Disassembly of section .plt.got:

0000000000001830 <__cxa_finalize@plt>:
    1830:	ff 25 c2 87 20 00    	jmp    QWORD PTR [rip+0x2087c2]        # 209ff8 <__cxa_finalize@GLIBC_2.2.5>
    1836:	66 90                	xchg   ax,ax

Disassembly of section .text:

0000000000001840 <_start>:
    1840:	31 ed                	xor    ebp,ebp
    1842:	49 89 d1             	mov    r9,rdx
    1845:	5e                   	pop    rsi
    1846:	48 89 e2             	mov    rdx,rsp
    1849:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
    184d:	50                   	push   rax
    184e:	54                   	push   rsp
    184f:	4c 8d 05 9a 5f 00 00 	lea    r8,[rip+0x5f9a]        # 77f0 <__libc_csu_fini>
    1856:	48 8d 0d 23 5f 00 00 	lea    rcx,[rip+0x5f23]        # 7780 <__libc_csu_init>
    185d:	48 8d 3d d6 24 00 00 	lea    rdi,[rip+0x24d6]        # 3d3a <main>
    1864:	ff 15 76 87 20 00    	call   QWORD PTR [rip+0x208776]        # 209fe0 <__libc_start_main@GLIBC_2.2.5>
    186a:	f4                   	hlt    
    186b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000001870 <deregister_tm_clones>:
    1870:	48 8d 3d a1 87 20 00 	lea    rdi,[rip+0x2087a1]        # 20a018 <__TMC_END__>
    1877:	55                   	push   rbp
    1878:	48 8d 05 99 87 20 00 	lea    rax,[rip+0x208799]        # 20a018 <__TMC_END__>
    187f:	48 39 f8             	cmp    rax,rdi
    1882:	48 89 e5             	mov    rbp,rsp
    1885:	74 19                	je     18a0 <deregister_tm_clones+0x30>
    1887:	48 8b 05 5a 87 20 00 	mov    rax,QWORD PTR [rip+0x20875a]        # 209fe8 <_ITM_deregisterTMCloneTable>
    188e:	48 85 c0             	test   rax,rax
    1891:	74 0d                	je     18a0 <deregister_tm_clones+0x30>
    1893:	5d                   	pop    rbp
    1894:	ff e0                	jmp    rax
    1896:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
    189d:	00 00 00 
    18a0:	5d                   	pop    rbp
    18a1:	c3                   	ret    
    18a2:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
    18a6:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
    18ad:	00 00 00 

00000000000018b0 <register_tm_clones>:
    18b0:	48 8d 3d 61 87 20 00 	lea    rdi,[rip+0x208761]        # 20a018 <__TMC_END__>
    18b7:	48 8d 35 5a 87 20 00 	lea    rsi,[rip+0x20875a]        # 20a018 <__TMC_END__>
    18be:	55                   	push   rbp
    18bf:	48 29 fe             	sub    rsi,rdi
    18c2:	48 89 e5             	mov    rbp,rsp
    18c5:	48 c1 fe 03          	sar    rsi,0x3
    18c9:	48 89 f0             	mov    rax,rsi
    18cc:	48 c1 e8 3f          	shr    rax,0x3f
    18d0:	48 01 c6             	add    rsi,rax
    18d3:	48 d1 fe             	sar    rsi,1
    18d6:	74 18                	je     18f0 <register_tm_clones+0x40>
    18d8:	48 8b 05 11 87 20 00 	mov    rax,QWORD PTR [rip+0x208711]        # 209ff0 <_ITM_registerTMCloneTable>
    18df:	48 85 c0             	test   rax,rax
    18e2:	74 0c                	je     18f0 <register_tm_clones+0x40>
    18e4:	5d                   	pop    rbp
    18e5:	ff e0                	jmp    rax
    18e7:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
    18ee:	00 00 
    18f0:	5d                   	pop    rbp
    18f1:	c3                   	ret    
    18f2:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
    18f6:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
    18fd:	00 00 00 

0000000000001900 <__do_global_dtors_aux>:
    1900:	80 3d 0a 87 20 00 00 	cmp    BYTE PTR [rip+0x20870a],0x0        # 20a011 <_edata>
    1907:	75 2f                	jne    1938 <__do_global_dtors_aux+0x38>
    1909:	48 83 3d e7 86 20 00 	cmp    QWORD PTR [rip+0x2086e7],0x0        # 209ff8 <__cxa_finalize@GLIBC_2.2.5>
    1910:	00 
    1911:	55                   	push   rbp
    1912:	48 89 e5             	mov    rbp,rsp
    1915:	74 0c                	je     1923 <__do_global_dtors_aux+0x23>
    1917:	48 8b 3d ea 86 20 00 	mov    rdi,QWORD PTR [rip+0x2086ea]        # 20a008 <__dso_handle>
    191e:	e8 0d ff ff ff       	call   1830 <__cxa_finalize@plt>
    1923:	e8 48 ff ff ff       	call   1870 <deregister_tm_clones>
    1928:	c6 05 e2 86 20 00 01 	mov    BYTE PTR [rip+0x2086e2],0x1        # 20a011 <_edata>
    192f:	5d                   	pop    rbp
    1930:	c3                   	ret    
    1931:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1938:	f3 c3                	repz ret 
    193a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

0000000000001940 <frame_dummy>:
    1940:	55                   	push   rbp
    1941:	48 89 e5             	mov    rbp,rsp
    1944:	5d                   	pop    rbp
    1945:	e9 66 ff ff ff       	jmp    18b0 <register_tm_clones>

000000000000194a <from_verifiable_secret_sharing_status>:
    194a:	55                   	push   rbp
    194b:	48 89 e5             	mov    rbp,rsp
    194e:	89 7d fc             	mov    DWORD PTR [rbp-0x4],edi
    1951:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
    1954:	83 c0 08             	add    eax,0x8
    1957:	83 f8 08             	cmp    eax,0x8
    195a:	77 62                	ja     19be <from_verifiable_secret_sharing_status+0x74>
    195c:	89 c0                	mov    eax,eax
    195e:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
    1965:	00 
    1966:	48 8d 05 a3 5e 00 00 	lea    rax,[rip+0x5ea3]        # 7810 <_IO_stdin_used+0x10>
    196d:	8b 04 02             	mov    eax,DWORD PTR [rdx+rax*1]
    1970:	48 63 d0             	movsxd rdx,eax
    1973:	48 8d 05 96 5e 00 00 	lea    rax,[rip+0x5e96]        # 7810 <_IO_stdin_used+0x10>
    197a:	48 01 d0             	add    rax,rdx
    197d:	ff e0                	jmp    rax
    197f:	b8 00 00 00 00       	mov    eax,0x0
    1984:	eb 3d                	jmp    19c3 <from_verifiable_secret_sharing_status+0x79>
    1986:	b8 ff ff ff ff       	mov    eax,0xffffffff
    198b:	eb 36                	jmp    19c3 <from_verifiable_secret_sharing_status+0x79>
    198d:	b8 f5 ff ff ff       	mov    eax,0xfffffff5
    1992:	eb 2f                	jmp    19c3 <from_verifiable_secret_sharing_status+0x79>
    1994:	b8 f4 ff ff ff       	mov    eax,0xfffffff4
    1999:	eb 28                	jmp    19c3 <from_verifiable_secret_sharing_status+0x79>
    199b:	b8 f3 ff ff ff       	mov    eax,0xfffffff3
    19a0:	eb 21                	jmp    19c3 <from_verifiable_secret_sharing_status+0x79>
    19a2:	b8 f2 ff ff ff       	mov    eax,0xfffffff2
    19a7:	eb 1a                	jmp    19c3 <from_verifiable_secret_sharing_status+0x79>
    19a9:	b8 f9 ff ff ff       	mov    eax,0xfffffff9
    19ae:	eb 13                	jmp    19c3 <from_verifiable_secret_sharing_status+0x79>
    19b0:	b8 fc ff ff ff       	mov    eax,0xfffffffc
    19b5:	eb 0c                	jmp    19c3 <from_verifiable_secret_sharing_status+0x79>
    19b7:	b8 fb ff ff ff       	mov    eax,0xfffffffb
    19bc:	eb 05                	jmp    19c3 <from_verifiable_secret_sharing_status+0x79>
    19be:	b8 ff ff ff ff       	mov    eax,0xffffffff
    19c3:	5d                   	pop    rbp
    19c4:	c3                   	ret    

00000000000019c5 <threshold_tree_ctx_new>:
    19c5:	55                   	push   rbp
    19c6:	48 89 e5             	mov    rbp,rsp
    19c9:	48 83 ec 10          	sub    rsp,0x10
    19cd:	bf 08 00 00 00       	mov    edi,0x8
    19d2:	e8 89 fb ff ff       	call   1560 <malloc@plt>
    19d7:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    19db:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    19e0:	75 07                	jne    19e9 <threshold_tree_ctx_new+0x24>
    19e2:	b8 00 00 00 00       	mov    eax,0x0
    19e7:	eb 0f                	jmp    19f8 <threshold_tree_ctx_new+0x33>
    19e9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    19ed:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
    19f4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    19f8:	c9                   	leave  
    19f9:	c3                   	ret    

00000000000019fa <threshold_tree_free_subtree_impl>:
    19fa:	55                   	push   rbp
    19fb:	48 89 e5             	mov    rbp,rsp
    19fe:	48 83 ec 20          	sub    rsp,0x20
    1a02:	48 89 7d e8          	mov    QWORD PTR [rbp-0x18],rdi
    1a06:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
    1a0b:	0f 84 02 01 00 00    	je     1b13 <threshold_tree_free_subtree_impl+0x119>
    1a11:	c6 45 ff 00          	mov    BYTE PTR [rbp-0x1],0x0
    1a15:	eb 25                	jmp    1a3c <threshold_tree_free_subtree_impl+0x42>
    1a17:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    1a1b:	48 8b 80 80 00 00 00 	mov    rax,QWORD PTR [rax+0x80]
    1a22:	0f b6 55 ff          	movzx  edx,BYTE PTR [rbp-0x1]
    1a26:	48 c1 e2 03          	shl    rdx,0x3
    1a2a:	48 01 d0             	add    rax,rdx
    1a2d:	48 8b 00             	mov    rax,QWORD PTR [rax]
    1a30:	48 89 c7             	mov    rdi,rax
    1a33:	e8 c2 ff ff ff       	call   19fa <threshold_tree_free_subtree_impl>
    1a38:	80 45 ff 01          	add    BYTE PTR [rbp-0x1],0x1
    1a3c:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    1a40:	0f b6 40 08          	movzx  eax,BYTE PTR [rax+0x8]
    1a44:	38 45 ff             	cmp    BYTE PTR [rbp-0x1],al
    1a47:	72 ce                	jb     1a17 <threshold_tree_free_subtree_impl+0x1d>
    1a49:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    1a4d:	48 8b 80 80 00 00 00 	mov    rax,QWORD PTR [rax+0x80]
    1a54:	48 89 c7             	mov    rdi,rax
    1a57:	e8 c4 fb ff ff       	call   1620 <free@plt>
    1a5c:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    1a60:	0f b6 40 09          	movzx  eax,BYTE PTR [rax+0x9]
    1a64:	0f b6 d0             	movzx  edx,al
    1a67:	48 89 d0             	mov    rax,rdx
    1a6a:	48 c1 e0 05          	shl    rax,0x5
    1a6e:	48 01 c2             	add    rdx,rax
    1a71:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    1a75:	48 8b 40 50          	mov    rax,QWORD PTR [rax+0x50]
    1a79:	be 00 00 00 00       	mov    esi,0x0
    1a7e:	48 89 c7             	mov    rdi,rax
    1a81:	e8 0a fa ff ff       	call   1490 <memset@plt>
    1a86:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    1a8a:	48 8b 40 50          	mov    rax,QWORD PTR [rax+0x50]
    1a8e:	48 89 c7             	mov    rdi,rax
    1a91:	e8 8a fb ff ff       	call   1620 <free@plt>
    1a96:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    1a9a:	48 83 c0 0a          	add    rax,0xa
    1a9e:	ba 20 00 00 00       	mov    edx,0x20
    1aa3:	be 00 00 00 00       	mov    esi,0x0
    1aa8:	48 89 c7             	mov    rdi,rax
    1aab:	e8 e0 f9 ff ff       	call   1490 <memset@plt>
    1ab0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    1ab4:	48 83 c0 2a          	add    rax,0x2a
    1ab8:	ba 21 00 00 00       	mov    edx,0x21
    1abd:	be 00 00 00 00       	mov    esi,0x0
    1ac2:	48 89 c7             	mov    rdi,rax
    1ac5:	e8 c6 f9 ff ff       	call   1490 <memset@plt>
    1aca:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    1ace:	48 83 c0 58          	add    rax,0x58
    1ad2:	ba 20 00 00 00       	mov    edx,0x20
    1ad7:	be 00 00 00 00       	mov    esi,0x0
    1adc:	48 89 c7             	mov    rdi,rax
    1adf:	e8 ac f9 ff ff       	call   1490 <memset@plt>
    1ae4:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    1ae8:	c6 40 78 00          	mov    BYTE PTR [rax+0x78],0x0
    1aec:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    1af0:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
    1af7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    1afb:	c6 40 08 00          	mov    BYTE PTR [rax+0x8],0x0
    1aff:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    1b03:	c6 40 09 00          	mov    BYTE PTR [rax+0x9],0x0
    1b07:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    1b0b:	48 89 c7             	mov    rdi,rax
    1b0e:	e8 0d fb ff ff       	call   1620 <free@plt>
    1b13:	90                   	nop
    1b14:	c9                   	leave  
    1b15:	c3                   	ret    

0000000000001b16 <threshold_tree_ctx_free>:
    1b16:	55                   	push   rbp
    1b17:	48 89 e5             	mov    rbp,rsp
    1b1a:	48 83 ec 10          	sub    rsp,0x10
    1b1e:	48 89 7d f8          	mov    QWORD PTR [rbp-0x8],rdi
    1b22:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    1b27:	74 1d                	je     1b46 <threshold_tree_ctx_free+0x30>
    1b29:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    1b2d:	48 8b 00             	mov    rax,QWORD PTR [rax]
    1b30:	48 89 c7             	mov    rdi,rax
    1b33:	e8 c2 fe ff ff       	call   19fa <threshold_tree_free_subtree_impl>
    1b38:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    1b3c:	48 89 c7             	mov    rdi,rax
    1b3f:	e8 dc fa ff ff       	call   1620 <free@plt>
    1b44:	eb 01                	jmp    1b47 <threshold_tree_ctx_free+0x31>
    1b46:	90                   	nop
    1b47:	c9                   	leave  
    1b48:	c3                   	ret    

0000000000001b49 <threshold_tree_check_complete_subtree_structure_impl>:
    1b49:	55                   	push   rbp
    1b4a:	48 89 e5             	mov    rbp,rsp
    1b4d:	48 83 ec 20          	sub    rsp,0x20
    1b51:	48 89 7d e8          	mov    QWORD PTR [rbp-0x18],rdi
    1b55:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
    1b5a:	75 07                	jne    1b63 <threshold_tree_check_complete_subtree_structure_impl+0x1a>
    1b5c:	b8 f6 ff ff ff       	mov    eax,0xfffffff6
    1b61:	eb 50                	jmp    1bb3 <threshold_tree_check_complete_subtree_structure_impl+0x6a>
    1b63:	c6 45 f7 00          	mov    BYTE PTR [rbp-0x9],0x0
    1b67:	eb 38                	jmp    1ba1 <threshold_tree_check_complete_subtree_structure_impl+0x58>
    1b69:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    1b6d:	48 8b 80 80 00 00 00 	mov    rax,QWORD PTR [rax+0x80]
    1b74:	0f b6 55 f7          	movzx  edx,BYTE PTR [rbp-0x9]
    1b78:	48 c1 e2 03          	shl    rdx,0x3
    1b7c:	48 01 d0             	add    rax,rdx
    1b7f:	48 8b 00             	mov    rax,QWORD PTR [rax]
    1b82:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    1b86:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    1b8a:	48 89 c7             	mov    rdi,rax
    1b8d:	e8 b7 ff ff ff       	call   1b49 <threshold_tree_check_complete_subtree_structure_impl>
    1b92:	85 c0                	test   eax,eax
    1b94:	74 07                	je     1b9d <threshold_tree_check_complete_subtree_structure_impl+0x54>
    1b96:	b8 f6 ff ff ff       	mov    eax,0xfffffff6
    1b9b:	eb 16                	jmp    1bb3 <threshold_tree_check_complete_subtree_structure_impl+0x6a>
    1b9d:	80 45 f7 01          	add    BYTE PTR [rbp-0x9],0x1
    1ba1:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    1ba5:	0f b6 40 08          	movzx  eax,BYTE PTR [rax+0x8]
    1ba9:	38 45 f7             	cmp    BYTE PTR [rbp-0x9],al
    1bac:	72 bb                	jb     1b69 <threshold_tree_check_complete_subtree_structure_impl+0x20>
    1bae:	b8 00 00 00 00       	mov    eax,0x0
    1bb3:	c9                   	leave  
    1bb4:	c3                   	ret    

0000000000001bb5 <threshold_tree_check_complete_structure>:
    1bb5:	55                   	push   rbp
    1bb6:	48 89 e5             	mov    rbp,rsp
    1bb9:	48 83 ec 10          	sub    rsp,0x10
    1bbd:	48 89 7d f8          	mov    QWORD PTR [rbp-0x8],rdi
    1bc1:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    1bc6:	75 07                	jne    1bcf <threshold_tree_check_complete_structure+0x1a>
    1bc8:	b8 f8 ff ff ff       	mov    eax,0xfffffff8
    1bcd:	eb 0f                	jmp    1bde <threshold_tree_check_complete_structure+0x29>
    1bcf:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    1bd3:	48 8b 00             	mov    rax,QWORD PTR [rax]
    1bd6:	48 89 c7             	mov    rdi,rax
    1bd9:	e8 6b ff ff ff       	call   1b49 <threshold_tree_check_complete_subtree_structure_impl>
    1bde:	c9                   	leave  
    1bdf:	c3                   	ret    

0000000000001be0 <threshold_tree_get_node_by_path_impl>:
    1be0:	55                   	push   rbp
    1be1:	48 89 e5             	mov    rbp,rsp
    1be4:	48 89 7d f8          	mov    QWORD PTR [rbp-0x8],rdi
    1be8:	48 89 75 f0          	mov    QWORD PTR [rbp-0x10],rsi
    1bec:	89 d0                	mov    eax,edx
    1bee:	48 89 4d e0          	mov    QWORD PTR [rbp-0x20],rcx
    1bf2:	88 45 ec             	mov    BYTE PTR [rbp-0x14],al
    1bf5:	eb 54                	jmp    1c4b <threshold_tree_get_node_by_path_impl+0x6b>
    1bf7:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    1bfc:	75 07                	jne    1c05 <threshold_tree_get_node_by_path_impl+0x25>
    1bfe:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    1c03:	eb 6a                	jmp    1c6f <threshold_tree_get_node_by_path_impl+0x8f>
    1c05:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    1c09:	0f b6 10             	movzx  edx,BYTE PTR [rax]
    1c0c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    1c10:	0f b6 40 08          	movzx  eax,BYTE PTR [rax+0x8]
    1c14:	38 c2                	cmp    dl,al
    1c16:	72 07                	jb     1c1f <threshold_tree_get_node_by_path_impl+0x3f>
    1c18:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    1c1d:	eb 50                	jmp    1c6f <threshold_tree_get_node_by_path_impl+0x8f>
    1c1f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    1c23:	48 8b 90 80 00 00 00 	mov    rdx,QWORD PTR [rax+0x80]
    1c2a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    1c2e:	0f b6 00             	movzx  eax,BYTE PTR [rax]
    1c31:	0f b6 c0             	movzx  eax,al
    1c34:	48 c1 e0 03          	shl    rax,0x3
    1c38:	48 01 d0             	add    rax,rdx
    1c3b:	48 8b 00             	mov    rax,QWORD PTR [rax]
    1c3e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    1c42:	48 83 45 f0 01       	add    QWORD PTR [rbp-0x10],0x1
    1c47:	80 6d ec 01          	sub    BYTE PTR [rbp-0x14],0x1
    1c4b:	80 7d ec 00          	cmp    BYTE PTR [rbp-0x14],0x0
    1c4f:	75 a6                	jne    1bf7 <threshold_tree_get_node_by_path_impl+0x17>
    1c51:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    1c56:	75 07                	jne    1c5f <threshold_tree_get_node_by_path_impl+0x7f>
    1c58:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    1c5d:	eb 10                	jmp    1c6f <threshold_tree_get_node_by_path_impl+0x8f>
    1c5f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
    1c63:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
    1c67:	48 89 10             	mov    QWORD PTR [rax],rdx
    1c6a:	b8 00 00 00 00       	mov    eax,0x0
    1c6f:	5d                   	pop    rbp
    1c70:	c3                   	ret    

0000000000001c71 <threshold_tree_get_node_by_path>:
    1c71:	55                   	push   rbp
    1c72:	48 89 e5             	mov    rbp,rsp
    1c75:	48 83 ec 40          	sub    rsp,0x40
    1c79:	48 89 7d d8          	mov    QWORD PTR [rbp-0x28],rdi
    1c7d:	48 89 75 d0          	mov    QWORD PTR [rbp-0x30],rsi
    1c81:	89 d0                	mov    eax,edx
    1c83:	48 89 4d c0          	mov    QWORD PTR [rbp-0x40],rcx
    1c87:	88 45 cc             	mov    BYTE PTR [rbp-0x34],al
    1c8a:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    1c91:	00 00 
    1c93:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    1c97:	31 c0                	xor    eax,eax
    1c99:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
    1c9e:	75 07                	jne    1ca7 <threshold_tree_get_node_by_path+0x36>
    1ca0:	b8 f8 ff ff ff       	mov    eax,0xfffffff8
    1ca5:	eb 3b                	jmp    1ce2 <threshold_tree_get_node_by_path+0x71>
    1ca7:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
    1cae:	00 
    1caf:	0f b6 55 cc          	movzx  edx,BYTE PTR [rbp-0x34]
    1cb3:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    1cb7:	48 8b 00             	mov    rax,QWORD PTR [rax]
    1cba:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
    1cbe:	48 8b 75 d0          	mov    rsi,QWORD PTR [rbp-0x30]
    1cc2:	48 89 c7             	mov    rdi,rax
    1cc5:	e8 16 ff ff ff       	call   1be0 <threshold_tree_get_node_by_path_impl>
    1cca:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
    1ccd:	48 83 7d c0 00       	cmp    QWORD PTR [rbp-0x40],0x0
    1cd2:	74 0b                	je     1cdf <threshold_tree_get_node_by_path+0x6e>
    1cd4:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
    1cd8:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
    1cdc:	48 89 10             	mov    QWORD PTR [rax],rdx
    1cdf:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
    1ce2:	48 8b 7d f8          	mov    rdi,QWORD PTR [rbp-0x8]
    1ce6:	64 48 33 3c 25 28 00 	xor    rdi,QWORD PTR fs:0x28
    1ced:	00 00 
    1cef:	74 05                	je     1cf6 <threshold_tree_get_node_by_path+0x85>
    1cf1:	e8 fa f9 ff ff       	call   16f0 <__stack_chk_fail@plt>
    1cf6:	c9                   	leave  
    1cf7:	c3                   	ret    

0000000000001cf8 <threshold_tree_get_node_by_id_impl>:
    1cf8:	55                   	push   rbp
    1cf9:	48 89 e5             	mov    rbp,rsp
    1cfc:	48 83 ec 30          	sub    rsp,0x30
    1d00:	48 89 7d e8          	mov    QWORD PTR [rbp-0x18],rdi
    1d04:	48 89 75 e0          	mov    QWORD PTR [rbp-0x20],rsi
    1d08:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
    1d0c:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
    1d11:	75 07                	jne    1d1a <threshold_tree_get_node_by_id_impl+0x22>
    1d13:	b8 fa ff ff ff       	mov    eax,0xfffffffa
    1d18:	eb 72                	jmp    1d8c <threshold_tree_get_node_by_id_impl+0x94>
    1d1a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    1d1e:	48 8b 00             	mov    rax,QWORD PTR [rax]
    1d21:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
    1d25:	75 12                	jne    1d39 <threshold_tree_get_node_by_id_impl+0x41>
    1d27:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    1d2b:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
    1d2f:	48 89 10             	mov    QWORD PTR [rax],rdx
    1d32:	b8 00 00 00 00       	mov    eax,0x0
    1d37:	eb 53                	jmp    1d8c <threshold_tree_get_node_by_id_impl+0x94>
    1d39:	c6 45 ff 00          	mov    BYTE PTR [rbp-0x1],0x0
    1d3d:	eb 3b                	jmp    1d7a <threshold_tree_get_node_by_id_impl+0x82>
    1d3f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    1d43:	48 8b 80 80 00 00 00 	mov    rax,QWORD PTR [rax+0x80]
    1d4a:	0f b6 55 ff          	movzx  edx,BYTE PTR [rbp-0x1]
    1d4e:	48 c1 e2 03          	shl    rdx,0x3
    1d52:	48 01 d0             	add    rax,rdx
    1d55:	48 8b 00             	mov    rax,QWORD PTR [rax]
    1d58:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
    1d5c:	48 8b 4d e0          	mov    rcx,QWORD PTR [rbp-0x20]
    1d60:	48 89 ce             	mov    rsi,rcx
    1d63:	48 89 c7             	mov    rdi,rax
    1d66:	e8 8d ff ff ff       	call   1cf8 <threshold_tree_get_node_by_id_impl>
    1d6b:	85 c0                	test   eax,eax
    1d6d:	75 07                	jne    1d76 <threshold_tree_get_node_by_id_impl+0x7e>
    1d6f:	b8 00 00 00 00       	mov    eax,0x0
    1d74:	eb 16                	jmp    1d8c <threshold_tree_get_node_by_id_impl+0x94>
    1d76:	80 45 ff 01          	add    BYTE PTR [rbp-0x1],0x1
    1d7a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    1d7e:	0f b6 40 08          	movzx  eax,BYTE PTR [rax+0x8]
    1d82:	38 45 ff             	cmp    BYTE PTR [rbp-0x1],al
    1d85:	72 b8                	jb     1d3f <threshold_tree_get_node_by_id_impl+0x47>
    1d87:	b8 fa ff ff ff       	mov    eax,0xfffffffa
    1d8c:	c9                   	leave  
    1d8d:	c3                   	ret    

0000000000001d8e <threshold_tree_get_node_by_id>:
    1d8e:	55                   	push   rbp
    1d8f:	48 89 e5             	mov    rbp,rsp
    1d92:	48 83 ec 40          	sub    rsp,0x40
    1d96:	48 89 7d d8          	mov    QWORD PTR [rbp-0x28],rdi
    1d9a:	48 89 75 d0          	mov    QWORD PTR [rbp-0x30],rsi
    1d9e:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
    1da2:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    1da9:	00 00 
    1dab:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    1daf:	31 c0                	xor    eax,eax
    1db1:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
    1db6:	75 07                	jne    1dbf <threshold_tree_get_node_by_id+0x31>
    1db8:	b8 f8 ff ff ff       	mov    eax,0xfffffff8
    1dbd:	eb 3a                	jmp    1df9 <threshold_tree_get_node_by_id+0x6b>
    1dbf:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
    1dc6:	00 
    1dc7:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    1dcb:	48 8b 00             	mov    rax,QWORD PTR [rax]
    1dce:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
    1dd2:	48 8b 4d d0          	mov    rcx,QWORD PTR [rbp-0x30]
    1dd6:	48 89 ce             	mov    rsi,rcx
    1dd9:	48 89 c7             	mov    rdi,rax
    1ddc:	e8 17 ff ff ff       	call   1cf8 <threshold_tree_get_node_by_id_impl>
    1de1:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
    1de4:	48 83 7d c8 00       	cmp    QWORD PTR [rbp-0x38],0x0
    1de9:	74 0b                	je     1df6 <threshold_tree_get_node_by_id+0x68>
    1deb:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
    1def:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    1df3:	48 89 10             	mov    QWORD PTR [rax],rdx
    1df6:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
    1df9:	48 8b 4d f8          	mov    rcx,QWORD PTR [rbp-0x8]
    1dfd:	64 48 33 0c 25 28 00 	xor    rcx,QWORD PTR fs:0x28
    1e04:	00 00 
    1e06:	74 05                	je     1e0d <threshold_tree_get_node_by_id+0x7f>
    1e08:	e8 e3 f8 ff ff       	call   16f0 <__stack_chk_fail@plt>
    1e0d:	c9                   	leave  
    1e0e:	c3                   	ret    

0000000000001e0f <threshold_tree_add_node>:
    1e0f:	55                   	push   rbp
    1e10:	48 89 e5             	mov    rbp,rsp
    1e13:	48 83 ec 50          	sub    rsp,0x50
    1e17:	48 89 7d d8          	mov    QWORD PTR [rbp-0x28],rdi
    1e1b:	48 89 75 d0          	mov    QWORD PTR [rbp-0x30],rsi
    1e1f:	89 d0                	mov    eax,edx
    1e21:	48 89 4d c0          	mov    QWORD PTR [rbp-0x40],rcx
    1e25:	44 89 c1             	mov    ecx,r8d
    1e28:	44 89 ca             	mov    edx,r9d
    1e2b:	88 45 cc             	mov    BYTE PTR [rbp-0x34],al
    1e2e:	89 c8                	mov    eax,ecx
    1e30:	88 45 c8             	mov    BYTE PTR [rbp-0x38],al
    1e33:	89 d0                	mov    eax,edx
    1e35:	88 45 bc             	mov    BYTE PTR [rbp-0x44],al
    1e38:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    1e3f:	00 00 
    1e41:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    1e45:	31 c0                	xor    eax,eax
    1e47:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
    1e4c:	75 0a                	jne    1e58 <threshold_tree_add_node+0x49>
    1e4e:	b8 f8 ff ff ff       	mov    eax,0xfffffff8
    1e53:	e9 a6 02 00 00       	jmp    20fe <threshold_tree_add_node+0x2ef>
    1e58:	80 7d bc 00          	cmp    BYTE PTR [rbp-0x44],0x0
    1e5c:	75 06                	jne    1e64 <threshold_tree_add_node+0x55>
    1e5e:	80 7d c8 00          	cmp    BYTE PTR [rbp-0x38],0x0
    1e62:	75 09                	jne    1e6d <threshold_tree_add_node+0x5e>
    1e64:	0f b6 45 bc          	movzx  eax,BYTE PTR [rbp-0x44]
    1e68:	3a 45 c8             	cmp    al,BYTE PTR [rbp-0x38]
    1e6b:	76 0a                	jbe    1e77 <threshold_tree_add_node+0x68>
    1e6d:	b8 fd ff ff ff       	mov    eax,0xfffffffd
    1e72:	e9 87 02 00 00       	jmp    20fe <threshold_tree_add_node+0x2ef>
    1e77:	48 8b 4d c0          	mov    rcx,QWORD PTR [rbp-0x40]
    1e7b:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    1e7f:	ba 00 00 00 00       	mov    edx,0x0
    1e84:	48 89 ce             	mov    rsi,rcx
    1e87:	48 89 c7             	mov    rdi,rax
    1e8a:	e8 ff fe ff ff       	call   1d8e <threshold_tree_get_node_by_id>
    1e8f:	85 c0                	test   eax,eax
    1e91:	75 0a                	jne    1e9d <threshold_tree_add_node+0x8e>
    1e93:	b8 f9 ff ff ff       	mov    eax,0xfffffff9
    1e98:	e9 61 02 00 00       	jmp    20fe <threshold_tree_add_node+0x2ef>
    1e9d:	be 90 00 00 00       	mov    esi,0x90
    1ea2:	bf 01 00 00 00       	mov    edi,0x1
    1ea7:	e8 74 f8 ff ff       	call   1720 <calloc@plt>
    1eac:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
    1eb0:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
    1eb5:	75 0a                	jne    1ec1 <threshold_tree_add_node+0xb2>
    1eb7:	b8 fb ff ff ff       	mov    eax,0xfffffffb
    1ebc:	e9 3d 02 00 00       	jmp    20fe <threshold_tree_add_node+0x2ef>
    1ec1:	80 7d cc 00          	cmp    BYTE PTR [rbp-0x34],0x0
    1ec5:	75 28                	jne    1eef <threshold_tree_add_node+0xe0>
    1ec7:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    1ecb:	48 8b 00             	mov    rax,QWORD PTR [rax]
    1ece:	48 85 c0             	test   rax,rax
    1ed1:	0f 85 0c 02 00 00    	jne    20e3 <threshold_tree_add_node+0x2d4>
    1ed7:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    1edb:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
    1edf:	48 89 10             	mov    QWORD PTR [rax],rdx
    1ee2:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
    1ee9:	00 
    1eea:	e9 a9 00 00 00       	jmp    1f98 <threshold_tree_add_node+0x189>
    1eef:	0f b6 45 cc          	movzx  eax,BYTE PTR [rbp-0x34]
    1ef3:	83 e8 01             	sub    eax,0x1
    1ef6:	0f b6 d0             	movzx  edx,al
    1ef9:	48 8d 4d e8          	lea    rcx,[rbp-0x18]
    1efd:	48 8b 75 d0          	mov    rsi,QWORD PTR [rbp-0x30]
    1f01:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    1f05:	48 89 c7             	mov    rdi,rax
    1f08:	e8 64 fd ff ff       	call   1c71 <threshold_tree_get_node_by_path>
    1f0d:	85 c0                	test   eax,eax
    1f0f:	0f 85 d1 01 00 00    	jne    20e6 <threshold_tree_add_node+0x2d7>
    1f15:	0f b6 45 cc          	movzx  eax,BYTE PTR [rbp-0x34]
    1f19:	48 8d 50 ff          	lea    rdx,[rax-0x1]
    1f1d:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
    1f21:	48 01 d0             	add    rax,rdx
    1f24:	0f b6 10             	movzx  edx,BYTE PTR [rax]
    1f27:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    1f2b:	0f b6 40 08          	movzx  eax,BYTE PTR [rax+0x8]
    1f2f:	38 c2                	cmp    dl,al
    1f31:	0f 83 b2 01 00 00    	jae    20e9 <threshold_tree_add_node+0x2da>
    1f37:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    1f3b:	48 8b 80 80 00 00 00 	mov    rax,QWORD PTR [rax+0x80]
    1f42:	0f b6 55 cc          	movzx  edx,BYTE PTR [rbp-0x34]
    1f46:	48 8d 4a ff          	lea    rcx,[rdx-0x1]
    1f4a:	48 8b 55 d0          	mov    rdx,QWORD PTR [rbp-0x30]
    1f4e:	48 01 ca             	add    rdx,rcx
    1f51:	0f b6 12             	movzx  edx,BYTE PTR [rdx]
    1f54:	0f b6 d2             	movzx  edx,dl
    1f57:	48 c1 e2 03          	shl    rdx,0x3
    1f5b:	48 01 d0             	add    rax,rdx
    1f5e:	48 8b 00             	mov    rax,QWORD PTR [rax]
    1f61:	48 85 c0             	test   rax,rax
    1f64:	0f 85 82 01 00 00    	jne    20ec <threshold_tree_add_node+0x2dd>
    1f6a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    1f6e:	48 8b 80 80 00 00 00 	mov    rax,QWORD PTR [rax+0x80]
    1f75:	0f b6 55 cc          	movzx  edx,BYTE PTR [rbp-0x34]
    1f79:	48 8d 4a ff          	lea    rcx,[rdx-0x1]
    1f7d:	48 8b 55 d0          	mov    rdx,QWORD PTR [rbp-0x30]
    1f81:	48 01 ca             	add    rdx,rcx
    1f84:	0f b6 12             	movzx  edx,BYTE PTR [rdx]
    1f87:	0f b6 d2             	movzx  edx,dl
    1f8a:	48 c1 e2 03          	shl    rdx,0x3
    1f8e:	48 01 c2             	add    rdx,rax
    1f91:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    1f95:	48 89 02             	mov    QWORD PTR [rdx],rax
    1f98:	0f b6 45 c8          	movzx  eax,BYTE PTR [rbp-0x38]
    1f9c:	be 08 00 00 00       	mov    esi,0x8
    1fa1:	48 89 c7             	mov    rdi,rax
    1fa4:	e8 77 f7 ff ff       	call   1720 <calloc@plt>
    1fa9:	48 89 c2             	mov    rdx,rax
    1fac:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    1fb0:	48 89 90 80 00 00 00 	mov    QWORD PTR [rax+0x80],rdx
    1fb7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    1fbb:	48 8b 80 80 00 00 00 	mov    rax,QWORD PTR [rax+0x80]
    1fc2:	48 85 c0             	test   rax,rax
    1fc5:	0f 84 04 01 00 00    	je     20cf <threshold_tree_add_node+0x2c0>
    1fcb:	0f b6 45 bc          	movzx  eax,BYTE PTR [rbp-0x44]
    1fcf:	be 21 00 00 00       	mov    esi,0x21
    1fd4:	48 89 c7             	mov    rdi,rax
    1fd7:	e8 44 f7 ff ff       	call   1720 <calloc@plt>
    1fdc:	48 89 c2             	mov    rdx,rax
    1fdf:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    1fe3:	48 89 50 50          	mov    QWORD PTR [rax+0x50],rdx
    1fe7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    1feb:	48 8b 40 50          	mov    rax,QWORD PTR [rax+0x50]
    1fef:	48 85 c0             	test   rax,rax
    1ff2:	0f 84 c1 00 00 00    	je     20b9 <threshold_tree_add_node+0x2aa>
    1ff8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    1ffc:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
    2000:	48 89 10             	mov    QWORD PTR [rax],rdx
    2003:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    2007:	0f b6 55 c8          	movzx  edx,BYTE PTR [rbp-0x38]
    200b:	88 50 08             	mov    BYTE PTR [rax+0x8],dl
    200e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    2012:	0f b6 55 bc          	movzx  edx,BYTE PTR [rbp-0x44]
    2016:	88 50 09             	mov    BYTE PTR [rax+0x9],dl
    2019:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
    201d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    2021:	48 89 90 88 00 00 00 	mov    QWORD PTR [rax+0x88],rdx
    2028:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    202c:	c6 40 78 00          	mov    BYTE PTR [rax+0x78],0x0
    2030:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    2034:	48 83 c0 0a          	add    rax,0xa
    2038:	ba 20 00 00 00       	mov    edx,0x20
    203d:	be 00 00 00 00       	mov    esi,0x0
    2042:	48 89 c7             	mov    rdi,rax
    2045:	e8 46 f4 ff ff       	call   1490 <memset@plt>
    204a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    204e:	48 83 c0 2a          	add    rax,0x2a
    2052:	ba 21 00 00 00       	mov    edx,0x21
    2057:	be 00 00 00 00       	mov    esi,0x0
    205c:	48 89 c7             	mov    rdi,rax
    205f:	e8 2c f4 ff ff       	call   1490 <memset@plt>
    2064:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    2068:	48 83 c0 58          	add    rax,0x58
    206c:	ba 20 00 00 00       	mov    edx,0x20
    2071:	be 00 00 00 00       	mov    esi,0x0
    2076:	48 89 c7             	mov    rdi,rax
    2079:	e8 12 f4 ff ff       	call   1490 <memset@plt>
    207e:	c6 45 e7 00          	mov    BYTE PTR [rbp-0x19],0x0
    2082:	eb 21                	jmp    20a5 <threshold_tree_add_node+0x296>
    2084:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    2088:	48 8b 80 80 00 00 00 	mov    rax,QWORD PTR [rax+0x80]
    208f:	0f b6 55 e7          	movzx  edx,BYTE PTR [rbp-0x19]
    2093:	48 c1 e2 03          	shl    rdx,0x3
    2097:	48 01 d0             	add    rax,rdx
    209a:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
    20a1:	80 45 e7 01          	add    BYTE PTR [rbp-0x19],0x1
    20a5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    20a9:	0f b6 40 08          	movzx  eax,BYTE PTR [rax+0x8]
    20ad:	38 45 e7             	cmp    BYTE PTR [rbp-0x19],al
    20b0:	72 d2                	jb     2084 <threshold_tree_add_node+0x275>
    20b2:	b8 00 00 00 00       	mov    eax,0x0
    20b7:	eb 45                	jmp    20fe <threshold_tree_add_node+0x2ef>
    20b9:	90                   	nop
    20ba:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    20be:	48 8b 80 80 00 00 00 	mov    rax,QWORD PTR [rax+0x80]
    20c5:	48 89 c7             	mov    rdi,rax
    20c8:	e8 53 f5 ff ff       	call   1620 <free@plt>
    20cd:	eb 01                	jmp    20d0 <threshold_tree_add_node+0x2c1>
    20cf:	90                   	nop
    20d0:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    20d4:	48 89 c7             	mov    rdi,rax
    20d7:	e8 44 f5 ff ff       	call   1620 <free@plt>
    20dc:	b8 fb ff ff ff       	mov    eax,0xfffffffb
    20e1:	eb 1b                	jmp    20fe <threshold_tree_add_node+0x2ef>
    20e3:	90                   	nop
    20e4:	eb 07                	jmp    20ed <threshold_tree_add_node+0x2de>
    20e6:	90                   	nop
    20e7:	eb 04                	jmp    20ed <threshold_tree_add_node+0x2de>
    20e9:	90                   	nop
    20ea:	eb 01                	jmp    20ed <threshold_tree_add_node+0x2de>
    20ec:	90                   	nop
    20ed:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    20f1:	48 89 c7             	mov    rdi,rax
    20f4:	e8 27 f5 ff ff       	call   1620 <free@plt>
    20f9:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    20fe:	48 8b 75 f8          	mov    rsi,QWORD PTR [rbp-0x8]
    2102:	64 48 33 34 25 28 00 	xor    rsi,QWORD PTR fs:0x28
    2109:	00 00 
    210b:	74 05                	je     2112 <threshold_tree_add_node+0x303>
    210d:	e8 de f5 ff ff       	call   16f0 <__stack_chk_fail@plt>
    2112:	c9                   	leave  
    2113:	c3                   	ret    

0000000000002114 <threshold_tree_share_secret_subtree_impl>:
    2114:	55                   	push   rbp
    2115:	48 89 e5             	mov    rbp,rsp
    2118:	48 83 ec 60          	sub    rsp,0x60
    211c:	48 89 7d a8          	mov    QWORD PTR [rbp-0x58],rdi
    2120:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    2127:	00 00 
    2129:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    212d:	31 c0                	xor    eax,eax
    212f:	48 8b 45 a8          	mov    rax,QWORD PTR [rbp-0x58]
    2133:	0f b6 40 08          	movzx  eax,BYTE PTR [rax+0x8]
    2137:	84 c0                	test   al,al
    2139:	75 0a                	jne    2145 <threshold_tree_share_secret_subtree_impl+0x31>
    213b:	b8 00 00 00 00       	mov    eax,0x0
    2140:	e9 43 02 00 00       	jmp    2388 <threshold_tree_share_secret_subtree_impl+0x274>
    2145:	c7 45 bc 00 00 00 00 	mov    DWORD PTR [rbp-0x44],0x0
    214c:	48 8b 45 a8          	mov    rax,QWORD PTR [rbp-0x58]
    2150:	0f b6 40 08          	movzx  eax,BYTE PTR [rax+0x8]
    2154:	0f b6 c0             	movzx  eax,al
    2157:	be 08 00 00 00       	mov    esi,0x8
    215c:	48 89 c7             	mov    rdi,rax
    215f:	e8 bc f5 ff ff       	call   1720 <calloc@plt>
    2164:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
    2168:	48 83 7d c8 00       	cmp    QWORD PTR [rbp-0x38],0x0
    216d:	0f 84 d7 01 00 00    	je     234a <threshold_tree_share_secret_subtree_impl+0x236>
    2173:	c6 45 b9 00          	mov    BYTE PTR [rbp-0x47],0x0
    2177:	eb 39                	jmp    21b2 <threshold_tree_share_secret_subtree_impl+0x9e>
    2179:	48 8b 45 a8          	mov    rax,QWORD PTR [rbp-0x58]
    217d:	48 8b 80 80 00 00 00 	mov    rax,QWORD PTR [rax+0x80]
    2184:	0f b6 55 b9          	movzx  edx,BYTE PTR [rbp-0x47]
    2188:	48 c1 e2 03          	shl    rdx,0x3
    218c:	48 01 d0             	add    rax,rdx
    218f:	48 8b 00             	mov    rax,QWORD PTR [rax]
    2192:	48 89 c1             	mov    rcx,rax
    2195:	0f b6 45 b9          	movzx  eax,BYTE PTR [rbp-0x47]
    2199:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
    21a0:	00 
    21a1:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    21a5:	48 01 c2             	add    rdx,rax
    21a8:	48 8b 01             	mov    rax,QWORD PTR [rcx]
    21ab:	48 89 02             	mov    QWORD PTR [rdx],rax
    21ae:	80 45 b9 01          	add    BYTE PTR [rbp-0x47],0x1
    21b2:	48 8b 45 a8          	mov    rax,QWORD PTR [rbp-0x58]
    21b6:	0f b6 40 08          	movzx  eax,BYTE PTR [rax+0x8]
    21ba:	38 45 b9             	cmp    BYTE PTR [rbp-0x47],al
    21bd:	72 ba                	jb     2179 <threshold_tree_share_secret_subtree_impl+0x65>
    21bf:	48 8b 45 a8          	mov    rax,QWORD PTR [rbp-0x58]
    21c3:	0f b6 40 08          	movzx  eax,BYTE PTR [rax+0x8]
    21c7:	0f b6 d0             	movzx  edx,al
    21ca:	48 8b 45 a8          	mov    rax,QWORD PTR [rbp-0x58]
    21ce:	0f b6 40 09          	movzx  eax,BYTE PTR [rax+0x9]
    21d2:	0f b6 c0             	movzx  eax,al
    21d5:	48 8b 4d a8          	mov    rcx,QWORD PTR [rbp-0x58]
    21d9:	48 8d 79 0a          	lea    rdi,[rcx+0xa]
    21dd:	48 8d 75 c0          	lea    rsi,[rbp-0x40]
    21e1:	48 8b 4d c8          	mov    rcx,QWORD PTR [rbp-0x38]
    21e5:	49 89 f1             	mov    r9,rsi
    21e8:	49 89 c8             	mov    r8,rcx
    21eb:	89 d1                	mov    ecx,edx
    21ed:	89 c2                	mov    edx,eax
    21ef:	be 20 00 00 00       	mov    esi,0x20
    21f4:	e8 1b 29 00 00       	call   4b14 <verifiable_secret_sharing_split_with_custom_ids>
    21f9:	89 c7                	mov    edi,eax
    21fb:	e8 4a f7 ff ff       	call   194a <from_verifiable_secret_sharing_status>
    2200:	89 45 bc             	mov    DWORD PTR [rbp-0x44],eax
    2203:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    2207:	48 89 c7             	mov    rdi,rax
    220a:	e8 11 f4 ff ff       	call   1620 <free@plt>
    220f:	83 7d bc 00          	cmp    DWORD PTR [rbp-0x44],0x0
    2213:	0f 85 34 01 00 00    	jne    234d <threshold_tree_share_secret_subtree_impl+0x239>
    2219:	48 8b 45 a8          	mov    rax,QWORD PTR [rbp-0x58]
    221d:	0f b6 40 09          	movzx  eax,BYTE PTR [rax+0x9]
    2221:	0f b6 d0             	movzx  edx,al
    2224:	48 8b 45 a8          	mov    rax,QWORD PTR [rbp-0x58]
    2228:	48 8b 48 50          	mov    rcx,QWORD PTR [rax+0x50]
    222c:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
    2230:	48 89 ce             	mov    rsi,rcx
    2233:	48 89 c7             	mov    rdi,rax
    2236:	e8 a8 2e 00 00       	call   50e3 <verifiable_secret_sharing_get_polynom_proofs>
    223b:	89 c7                	mov    edi,eax
    223d:	e8 08 f7 ff ff       	call   194a <from_verifiable_secret_sharing_status>
    2242:	89 45 bc             	mov    DWORD PTR [rbp-0x44],eax
    2245:	83 7d bc 00          	cmp    DWORD PTR [rbp-0x44],0x0
    2249:	0f 85 01 01 00 00    	jne    2350 <threshold_tree_share_secret_subtree_impl+0x23c>
    224f:	c6 45 ba 00          	mov    BYTE PTR [rbp-0x46],0x0
    2253:	e9 85 00 00 00       	jmp    22dd <threshold_tree_share_secret_subtree_impl+0x1c9>
    2258:	48 8b 45 a8          	mov    rax,QWORD PTR [rbp-0x58]
    225c:	48 8b 80 80 00 00 00 	mov    rax,QWORD PTR [rax+0x80]
    2263:	0f b6 55 ba          	movzx  edx,BYTE PTR [rbp-0x46]
    2267:	48 c1 e2 03          	shl    rdx,0x3
    226b:	48 01 d0             	add    rax,rdx
    226e:	48 8b 00             	mov    rax,QWORD PTR [rax]
    2271:	48 8d 48 2a          	lea    rcx,[rax+0x2a]
    2275:	0f b6 75 ba          	movzx  esi,BYTE PTR [rbp-0x46]
    2279:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
    227d:	48 8d 55 d0          	lea    rdx,[rbp-0x30]
    2281:	48 89 c7             	mov    rdi,rax
    2284:	e8 9c 2c 00 00       	call   4f25 <verifiable_secret_sharing_get_share_and_proof>
    2289:	89 c7                	mov    edi,eax
    228b:	e8 ba f6 ff ff       	call   194a <from_verifiable_secret_sharing_status>
    2290:	89 45 bc             	mov    DWORD PTR [rbp-0x44],eax
    2293:	83 7d bc 00          	cmp    DWORD PTR [rbp-0x44],0x0
    2297:	0f 85 b6 00 00 00    	jne    2353 <threshold_tree_share_secret_subtree_impl+0x23f>
    229d:	48 8b 45 a8          	mov    rax,QWORD PTR [rbp-0x58]
    22a1:	48 8b 80 80 00 00 00 	mov    rax,QWORD PTR [rax+0x80]
    22a8:	0f b6 55 ba          	movzx  edx,BYTE PTR [rbp-0x46]
    22ac:	48 c1 e2 03          	shl    rdx,0x3
    22b0:	48 01 d0             	add    rax,rdx
    22b3:	48 8b 00             	mov    rax,QWORD PTR [rax]
    22b6:	48 8d 48 0a          	lea    rcx,[rax+0xa]
    22ba:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
    22be:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
    22c2:	48 89 01             	mov    QWORD PTR [rcx],rax
    22c5:	48 89 51 08          	mov    QWORD PTR [rcx+0x8],rdx
    22c9:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
    22cd:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
    22d1:	48 89 41 10          	mov    QWORD PTR [rcx+0x10],rax
    22d5:	48 89 51 18          	mov    QWORD PTR [rcx+0x18],rdx
    22d9:	80 45 ba 01          	add    BYTE PTR [rbp-0x46],0x1
    22dd:	48 8b 45 a8          	mov    rax,QWORD PTR [rbp-0x58]
    22e1:	0f b6 40 08          	movzx  eax,BYTE PTR [rax+0x8]
    22e5:	38 45 ba             	cmp    BYTE PTR [rbp-0x46],al
    22e8:	0f 82 6a ff ff ff    	jb     2258 <threshold_tree_share_secret_subtree_impl+0x144>
    22ee:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
    22f2:	48 89 c7             	mov    rdi,rax
    22f5:	e8 a9 37 00 00       	call   5aa3 <verifiable_secret_sharing_free_shares>
    22fa:	48 c7 45 c0 00 00 00 	mov    QWORD PTR [rbp-0x40],0x0
    2301:	00 
    2302:	c6 45 bb 00          	mov    BYTE PTR [rbp-0x45],0x0
    2306:	eb 2e                	jmp    2336 <threshold_tree_share_secret_subtree_impl+0x222>
    2308:	48 8b 45 a8          	mov    rax,QWORD PTR [rbp-0x58]
    230c:	48 8b 80 80 00 00 00 	mov    rax,QWORD PTR [rax+0x80]
    2313:	0f b6 55 bb          	movzx  edx,BYTE PTR [rbp-0x45]
    2317:	48 c1 e2 03          	shl    rdx,0x3
    231b:	48 01 d0             	add    rax,rdx
    231e:	48 8b 00             	mov    rax,QWORD PTR [rax]
    2321:	48 89 c7             	mov    rdi,rax
    2324:	e8 eb fd ff ff       	call   2114 <threshold_tree_share_secret_subtree_impl>
    2329:	89 45 bc             	mov    DWORD PTR [rbp-0x44],eax
    232c:	83 7d bc 00          	cmp    DWORD PTR [rbp-0x44],0x0
    2330:	75 24                	jne    2356 <threshold_tree_share_secret_subtree_impl+0x242>
    2332:	80 45 bb 01          	add    BYTE PTR [rbp-0x45],0x1
    2336:	48 8b 45 a8          	mov    rax,QWORD PTR [rbp-0x58]
    233a:	0f b6 40 08          	movzx  eax,BYTE PTR [rax+0x8]
    233e:	38 45 bb             	cmp    BYTE PTR [rbp-0x45],al
    2341:	72 c5                	jb     2308 <threshold_tree_share_secret_subtree_impl+0x1f4>
    2343:	b8 00 00 00 00       	mov    eax,0x0
    2348:	eb 3e                	jmp    2388 <threshold_tree_share_secret_subtree_impl+0x274>
    234a:	90                   	nop
    234b:	eb 0a                	jmp    2357 <threshold_tree_share_secret_subtree_impl+0x243>
    234d:	90                   	nop
    234e:	eb 07                	jmp    2357 <threshold_tree_share_secret_subtree_impl+0x243>
    2350:	90                   	nop
    2351:	eb 04                	jmp    2357 <threshold_tree_share_secret_subtree_impl+0x243>
    2353:	90                   	nop
    2354:	eb 01                	jmp    2357 <threshold_tree_share_secret_subtree_impl+0x243>
    2356:	90                   	nop
    2357:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    235b:	48 89 c7             	mov    rdi,rax
    235e:	e8 bd f2 ff ff       	call   1620 <free@plt>
    2363:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
    2367:	48 89 c7             	mov    rdi,rax
    236a:	e8 34 37 00 00       	call   5aa3 <verifiable_secret_sharing_free_shares>
    236f:	48 8d 45 d0          	lea    rax,[rbp-0x30]
    2373:	ba 20 00 00 00       	mov    edx,0x20
    2378:	be 00 00 00 00       	mov    esi,0x0
    237d:	48 89 c7             	mov    rdi,rax
    2380:	e8 0b f1 ff ff       	call   1490 <memset@plt>
    2385:	8b 45 bc             	mov    eax,DWORD PTR [rbp-0x44]
    2388:	48 8b 75 f8          	mov    rsi,QWORD PTR [rbp-0x8]
    238c:	64 48 33 34 25 28 00 	xor    rsi,QWORD PTR fs:0x28
    2393:	00 00 
    2395:	74 05                	je     239c <threshold_tree_share_secret_subtree_impl+0x288>
    2397:	e8 54 f3 ff ff       	call   16f0 <__stack_chk_fail@plt>
    239c:	c9                   	leave  
    239d:	c3                   	ret    

000000000000239e <threshold_tree_share_secret>:
    239e:	55                   	push   rbp
    239f:	48 89 e5             	mov    rbp,rsp
    23a2:	48 83 ec 20          	sub    rsp,0x20
    23a6:	48 89 7d e8          	mov    QWORD PTR [rbp-0x18],rdi
    23aa:	48 89 75 e0          	mov    QWORD PTR [rbp-0x20],rsi
    23ae:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    23b2:	48 89 c7             	mov    rdi,rax
    23b5:	e8 fb f7 ff ff       	call   1bb5 <threshold_tree_check_complete_structure>
    23ba:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
    23bd:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
    23c1:	74 05                	je     23c8 <threshold_tree_share_secret+0x2a>
    23c3:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
    23c6:	eb 2e                	jmp    23f6 <threshold_tree_share_secret+0x58>
    23c8:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    23cc:	48 8b 00             	mov    rax,QWORD PTR [rax]
    23cf:	48 8d 48 0a          	lea    rcx,[rax+0xa]
    23d3:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
    23d7:	ba 20 00 00 00       	mov    edx,0x20
    23dc:	48 89 c6             	mov    rsi,rax
    23df:	48 89 cf             	mov    rdi,rcx
    23e2:	e8 09 f4 ff ff       	call   17f0 <memcpy@plt>
    23e7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    23eb:	48 8b 00             	mov    rax,QWORD PTR [rax]
    23ee:	48 89 c7             	mov    rdi,rax
    23f1:	e8 1e fd ff ff       	call   2114 <threshold_tree_share_secret_subtree_impl>
    23f6:	c9                   	leave  
    23f7:	c3                   	ret    

00000000000023f8 <generate_all_combinations_impl>:
    23f8:	55                   	push   rbp
    23f9:	48 89 e5             	mov    rbp,rsp
    23fc:	48 83 ec 30          	sub    rsp,0x30
    2400:	48 89 7d e8          	mov    QWORD PTR [rbp-0x18],rdi
    2404:	89 c8                	mov    eax,ecx
    2406:	4c 89 45 d0          	mov    QWORD PTR [rbp-0x30],r8
    240a:	44 89 cf             	mov    edi,r9d
    240d:	89 f1                	mov    ecx,esi
    240f:	88 4d e4             	mov    BYTE PTR [rbp-0x1c],cl
    2412:	88 55 e0             	mov    BYTE PTR [rbp-0x20],dl
    2415:	88 45 dc             	mov    BYTE PTR [rbp-0x24],al
    2418:	89 f8                	mov    eax,edi
    241a:	88 45 d8             	mov    BYTE PTR [rbp-0x28],al
    241d:	0f b6 45 d8          	movzx  eax,BYTE PTR [rbp-0x28]
    2421:	3a 45 dc             	cmp    al,BYTE PTR [rbp-0x24]
    2424:	72 78                	jb     249e <generate_all_combinations_impl+0xa6>
    2426:	0f b6 45 dc          	movzx  eax,BYTE PTR [rbp-0x24]
    242a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    242e:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
    2432:	48 8b 00             	mov    rax,QWORD PTR [rax]
    2435:	48 83 c0 01          	add    rax,0x1
    2439:	48 0f af 45 f8       	imul   rax,QWORD PTR [rbp-0x8]
    243e:	48 89 c2             	mov    rdx,rax
    2441:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
    2445:	48 8b 00             	mov    rax,QWORD PTR [rax]
    2448:	48 89 d6             	mov    rsi,rdx
    244b:	48 89 c7             	mov    rdi,rax
    244e:	e8 6d f3 ff ff       	call   17c0 <realloc@plt>
    2453:	48 89 c2             	mov    rdx,rax
    2456:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
    245a:	48 89 10             	mov    QWORD PTR [rax],rdx
    245d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
    2461:	48 8b 10             	mov    rdx,QWORD PTR [rax]
    2464:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
    2468:	48 8b 00             	mov    rax,QWORD PTR [rax]
    246b:	48 0f af 45 f8       	imul   rax,QWORD PTR [rbp-0x8]
    2470:	48 8d 0c 02          	lea    rcx,[rdx+rax*1]
    2474:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
    2478:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
    247c:	48 89 c6             	mov    rsi,rax
    247f:	48 89 cf             	mov    rdi,rcx
    2482:	e8 69 f3 ff ff       	call   17f0 <memcpy@plt>
    2487:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
    248b:	48 8b 00             	mov    rax,QWORD PTR [rax]
    248e:	48 8d 50 01          	lea    rdx,[rax+0x1]
    2492:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
    2496:	48 89 10             	mov    QWORD PTR [rax],rdx
    2499:	e9 9f 00 00 00       	jmp    253d <generate_all_combinations_impl+0x145>
    249e:	0f b6 45 e4          	movzx  eax,BYTE PTR [rbp-0x1c]
    24a2:	3a 45 e0             	cmp    al,BYTE PTR [rbp-0x20]
    24a5:	0f 83 91 00 00 00    	jae    253c <generate_all_combinations_impl+0x144>
    24ab:	0f b6 55 e4          	movzx  edx,BYTE PTR [rbp-0x1c]
    24af:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    24b3:	48 01 d0             	add    rax,rdx
    24b6:	0f b6 4d d8          	movzx  ecx,BYTE PTR [rbp-0x28]
    24ba:	48 8b 55 d0          	mov    rdx,QWORD PTR [rbp-0x30]
    24be:	48 01 ca             	add    rdx,rcx
    24c1:	0f b6 00             	movzx  eax,BYTE PTR [rax]
    24c4:	88 02                	mov    BYTE PTR [rdx],al
    24c6:	0f b6 45 d8          	movzx  eax,BYTE PTR [rbp-0x28]
    24ca:	83 c0 01             	add    eax,0x1
    24cd:	44 0f b6 c0          	movzx  r8d,al
    24d1:	0f b6 4d dc          	movzx  ecx,BYTE PTR [rbp-0x24]
    24d5:	0f b6 55 e0          	movzx  edx,BYTE PTR [rbp-0x20]
    24d9:	0f b6 45 e4          	movzx  eax,BYTE PTR [rbp-0x1c]
    24dd:	83 c0 01             	add    eax,0x1
    24e0:	0f b6 f0             	movzx  esi,al
    24e3:	48 8b 7d d0          	mov    rdi,QWORD PTR [rbp-0x30]
    24e7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    24eb:	ff 75 18             	push   QWORD PTR [rbp+0x18]
    24ee:	ff 75 10             	push   QWORD PTR [rbp+0x10]
    24f1:	45 89 c1             	mov    r9d,r8d
    24f4:	49 89 f8             	mov    r8,rdi
    24f7:	48 89 c7             	mov    rdi,rax
    24fa:	e8 f9 fe ff ff       	call   23f8 <generate_all_combinations_impl>
    24ff:	48 83 c4 10          	add    rsp,0x10
    2503:	44 0f b6 45 d8       	movzx  r8d,BYTE PTR [rbp-0x28]
    2508:	0f b6 4d dc          	movzx  ecx,BYTE PTR [rbp-0x24]
    250c:	0f b6 55 e0          	movzx  edx,BYTE PTR [rbp-0x20]
    2510:	0f b6 45 e4          	movzx  eax,BYTE PTR [rbp-0x1c]
    2514:	83 c0 01             	add    eax,0x1
    2517:	0f b6 f0             	movzx  esi,al
    251a:	48 8b 7d d0          	mov    rdi,QWORD PTR [rbp-0x30]
    251e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    2522:	ff 75 18             	push   QWORD PTR [rbp+0x18]
    2525:	ff 75 10             	push   QWORD PTR [rbp+0x10]
    2528:	45 89 c1             	mov    r9d,r8d
    252b:	49 89 f8             	mov    r8,rdi
    252e:	48 89 c7             	mov    rdi,rax
    2531:	e8 c2 fe ff ff       	call   23f8 <generate_all_combinations_impl>
    2536:	48 83 c4 10          	add    rsp,0x10
    253a:	eb 01                	jmp    253d <generate_all_combinations_impl+0x145>
    253c:	90                   	nop
    253d:	c9                   	leave  
    253e:	c3                   	ret    

000000000000253f <get_all_combinations>:
    253f:	55                   	push   rbp
    2540:	48 89 e5             	mov    rbp,rsp
    2543:	41 56                	push   r14
    2545:	41 55                	push   r13
    2547:	41 54                	push   r12
    2549:	53                   	push   rbx
    254a:	48 83 ec 60          	sub    rsp,0x60
    254e:	89 f0                	mov    eax,esi
    2550:	48 89 55 a0          	mov    QWORD PTR [rbp-0x60],rdx
    2554:	48 89 4d 98          	mov    QWORD PTR [rbp-0x68],rcx
    2558:	89 fa                	mov    edx,edi
    255a:	88 55 ac             	mov    BYTE PTR [rbp-0x54],dl
    255d:	88 45 a8             	mov    BYTE PTR [rbp-0x58],al
    2560:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    2567:	00 00 
    2569:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
    256d:	31 c0                	xor    eax,eax
    256f:	48 89 e0             	mov    rax,rsp
    2572:	48 89 c3             	mov    rbx,rax
    2575:	48 83 7d a0 00       	cmp    QWORD PTR [rbp-0x60],0x0
    257a:	0f 84 3e 01 00 00    	je     26be <get_all_combinations+0x17f>
    2580:	48 8b 45 a0          	mov    rax,QWORD PTR [rbp-0x60]
    2584:	48 8b 00             	mov    rax,QWORD PTR [rax]
    2587:	48 85 c0             	test   rax,rax
    258a:	0f 85 31 01 00 00    	jne    26c1 <get_all_combinations+0x182>
    2590:	0f b6 45 ac          	movzx  eax,BYTE PTR [rbp-0x54]
    2594:	0f b6 d0             	movzx  edx,al
    2597:	48 83 ea 01          	sub    rdx,0x1
    259b:	48 89 55 b8          	mov    QWORD PTR [rbp-0x48],rdx
    259f:	0f b6 d0             	movzx  edx,al
    25a2:	49 89 d2             	mov    r10,rdx
    25a5:	41 bb 00 00 00 00    	mov    r11d,0x0
    25ab:	0f b6 d0             	movzx  edx,al
    25ae:	49 89 d0             	mov    r8,rdx
    25b1:	41 b9 00 00 00 00    	mov    r9d,0x0
    25b7:	0f b6 c0             	movzx  eax,al
    25ba:	ba 10 00 00 00       	mov    edx,0x10
    25bf:	48 83 ea 01          	sub    rdx,0x1
    25c3:	48 01 d0             	add    rax,rdx
    25c6:	be 10 00 00 00       	mov    esi,0x10
    25cb:	ba 00 00 00 00       	mov    edx,0x0
    25d0:	48 f7 f6             	div    rsi
    25d3:	48 6b c0 10          	imul   rax,rax,0x10
    25d7:	48 29 c4             	sub    rsp,rax
    25da:	48 89 e0             	mov    rax,rsp
    25dd:	48 83 c0 00          	add    rax,0x0
    25e1:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
    25e5:	c6 45 b7 00          	mov    BYTE PTR [rbp-0x49],0x0
    25e9:	eb 15                	jmp    2600 <get_all_combinations+0xc1>
    25eb:	0f b6 45 b7          	movzx  eax,BYTE PTR [rbp-0x49]
    25ef:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
    25f3:	48 98                	cdqe   
    25f5:	0f b6 4d b7          	movzx  ecx,BYTE PTR [rbp-0x49]
    25f9:	88 0c 02             	mov    BYTE PTR [rdx+rax*1],cl
    25fc:	80 45 b7 01          	add    BYTE PTR [rbp-0x49],0x1
    2600:	0f b6 45 b7          	movzx  eax,BYTE PTR [rbp-0x49]
    2604:	3a 45 ac             	cmp    al,BYTE PTR [rbp-0x54]
    2607:	72 e2                	jb     25eb <get_all_combinations+0xac>
    2609:	48 8b 45 98          	mov    rax,QWORD PTR [rbp-0x68]
    260d:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
    2614:	bf 00 00 00 00       	mov    edi,0x0
    2619:	e8 42 ef ff ff       	call   1560 <malloc@plt>
    261e:	48 89 c2             	mov    rdx,rax
    2621:	48 8b 45 a0          	mov    rax,QWORD PTR [rbp-0x60]
    2625:	48 89 10             	mov    QWORD PTR [rax],rdx
    2628:	0f b6 45 a8          	movzx  eax,BYTE PTR [rbp-0x58]
    262c:	48 89 e2             	mov    rdx,rsp
    262f:	49 89 d4             	mov    r12,rdx
    2632:	0f b6 d0             	movzx  edx,al
    2635:	48 83 ea 01          	sub    rdx,0x1
    2639:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
    263d:	0f b6 d0             	movzx  edx,al
    2640:	48 89 55 80          	mov    QWORD PTR [rbp-0x80],rdx
    2644:	48 c7 45 88 00 00 00 	mov    QWORD PTR [rbp-0x78],0x0
    264b:	00 
    264c:	0f b6 d0             	movzx  edx,al
    264f:	49 89 d5             	mov    r13,rdx
    2652:	41 be 00 00 00 00    	mov    r14d,0x0
    2658:	0f b6 c0             	movzx  eax,al
    265b:	ba 10 00 00 00       	mov    edx,0x10
    2660:	48 83 ea 01          	sub    rdx,0x1
    2664:	48 01 d0             	add    rax,rdx
    2667:	bf 10 00 00 00       	mov    edi,0x10
    266c:	ba 00 00 00 00       	mov    edx,0x0
    2671:	48 f7 f7             	div    rdi
    2674:	48 6b c0 10          	imul   rax,rax,0x10
    2678:	48 29 c4             	sub    rsp,rax
    267b:	48 89 e0             	mov    rax,rsp
    267e:	48 83 c0 00          	add    rax,0x0
    2682:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
    2686:	48 8b 75 d0          	mov    rsi,QWORD PTR [rbp-0x30]
    268a:	0f b6 4d a8          	movzx  ecx,BYTE PTR [rbp-0x58]
    268e:	0f b6 55 ac          	movzx  edx,BYTE PTR [rbp-0x54]
    2692:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
    2696:	ff 75 98             	push   QWORD PTR [rbp-0x68]
    2699:	ff 75 a0             	push   QWORD PTR [rbp-0x60]
    269c:	41 b9 00 00 00 00    	mov    r9d,0x0
    26a2:	49 89 f0             	mov    r8,rsi
    26a5:	be 00 00 00 00       	mov    esi,0x0
    26aa:	48 89 c7             	mov    rdi,rax
    26ad:	e8 46 fd ff ff       	call   23f8 <generate_all_combinations_impl>
    26b2:	48 83 c4 10          	add    rsp,0x10
    26b6:	4c 89 e4             	mov    rsp,r12
    26b9:	48 89 dc             	mov    rsp,rbx
    26bc:	eb 07                	jmp    26c5 <get_all_combinations+0x186>
    26be:	90                   	nop
    26bf:	eb 01                	jmp    26c2 <get_all_combinations+0x183>
    26c1:	90                   	nop
    26c2:	48 89 dc             	mov    rsp,rbx
    26c5:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    26c9:	64 48 33 04 25 28 00 	xor    rax,QWORD PTR fs:0x28
    26d0:	00 00 
    26d2:	74 05                	je     26d9 <get_all_combinations+0x19a>
    26d4:	e8 17 f0 ff ff       	call   16f0 <__stack_chk_fail@plt>
    26d9:	48 8d 65 e0          	lea    rsp,[rbp-0x20]
    26dd:	5b                   	pop    rbx
    26de:	41 5c                	pop    r12
    26e0:	41 5d                	pop    r13
    26e2:	41 5e                	pop    r14
    26e4:	5d                   	pop    rbp
    26e5:	c3                   	ret    

00000000000026e6 <test_threshold_tree_verify_all_shares_impl>:
    26e6:	55                   	push   rbp
    26e7:	48 89 e5             	mov    rbp,rsp
    26ea:	53                   	push   rbx
    26eb:	48 83 ec 38          	sub    rsp,0x38
    26ef:	48 89 7d c8          	mov    QWORD PTR [rbp-0x38],rdi
    26f3:	64 48 8b 34 25 28 00 	mov    rsi,QWORD PTR fs:0x28
    26fa:	00 00 
    26fc:	48 89 75 e8          	mov    QWORD PTR [rbp-0x18],rsi
    2700:	31 f6                	xor    esi,esi
    2702:	48 89 e6             	mov    rsi,rsp
    2705:	49 89 f1             	mov    r9,rsi
    2708:	48 83 7d c8 00       	cmp    QWORD PTR [rbp-0x38],0x0
    270d:	75 0a                	jne    2719 <test_threshold_tree_verify_all_shares_impl+0x33>
    270f:	b8 00 00 00 00       	mov    eax,0x0
    2714:	e9 1d 01 00 00       	jmp    2836 <test_threshold_tree_verify_all_shares_impl+0x150>
    2719:	48 8b 75 c8          	mov    rsi,QWORD PTR [rbp-0x38]
    271d:	0f b6 76 08          	movzx  esi,BYTE PTR [rsi+0x8]
    2721:	40 0f b6 fe          	movzx  edi,sil
    2725:	48 83 ef 01          	sub    rdi,0x1
    2729:	48 89 7d d8          	mov    QWORD PTR [rbp-0x28],rdi
    272d:	40 0f b6 fe          	movzx  edi,sil
    2731:	48 89 f8             	mov    rax,rdi
    2734:	ba 00 00 00 00       	mov    edx,0x0
    2739:	4c 69 c2 40 01 00 00 	imul   r8,rdx,0x140
    2740:	48 6b f8 00          	imul   rdi,rax,0x0
    2744:	4c 01 c7             	add    rdi,r8
    2747:	41 b8 40 01 00 00    	mov    r8d,0x140
    274d:	49 f7 e0             	mul    r8
    2750:	48 01 d7             	add    rdi,rdx
    2753:	48 89 fa             	mov    rdx,rdi
    2756:	40 0f b6 d6          	movzx  edx,sil
    275a:	48 89 d0             	mov    rax,rdx
    275d:	48 c1 e0 02          	shl    rax,0x2
    2761:	48 01 d0             	add    rax,rdx
    2764:	48 c1 e0 03          	shl    rax,0x3
    2768:	40 0f b6 c6          	movzx  eax,sil
    276c:	48 89 c1             	mov    rcx,rax
    276f:	bb 00 00 00 00       	mov    ebx,0x0
    2774:	48 69 d3 40 01 00 00 	imul   rdx,rbx,0x140
    277b:	48 6b c1 00          	imul   rax,rcx,0x0
    277f:	48 8d 3c 02          	lea    rdi,[rdx+rax*1]
    2783:	b8 40 01 00 00       	mov    eax,0x140
    2788:	48 f7 e1             	mul    rcx
    278b:	48 8d 0c 17          	lea    rcx,[rdi+rdx*1]
    278f:	48 89 ca             	mov    rdx,rcx
    2792:	40 0f b6 d6          	movzx  edx,sil
    2796:	48 89 d0             	mov    rax,rdx
    2799:	48 c1 e0 02          	shl    rax,0x2
    279d:	48 01 d0             	add    rax,rdx
    27a0:	48 c1 e0 03          	shl    rax,0x3
    27a4:	48 8d 50 07          	lea    rdx,[rax+0x7]
    27a8:	b8 10 00 00 00       	mov    eax,0x10
    27ad:	48 83 e8 01          	sub    rax,0x1
    27b1:	48 01 d0             	add    rax,rdx
    27b4:	bb 10 00 00 00       	mov    ebx,0x10
    27b9:	ba 00 00 00 00       	mov    edx,0x0
    27be:	48 f7 f3             	div    rbx
    27c1:	48 6b c0 10          	imul   rax,rax,0x10
    27c5:	48 29 c4             	sub    rsp,rax
    27c8:	48 89 e0             	mov    rax,rsp
    27cb:	48 83 c0 07          	add    rax,0x7
    27cf:	48 c1 e8 03          	shr    rax,0x3
    27d3:	48 c1 e0 03          	shl    rax,0x3
    27d7:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
    27db:	c6 45 d7 00          	mov    BYTE PTR [rbp-0x29],0x0
    27df:	eb 2b                	jmp    280c <test_threshold_tree_verify_all_shares_impl+0x126>
    27e1:	0f b6 45 d7          	movzx  eax,BYTE PTR [rbp-0x29]
    27e5:	0f b6 4d d7          	movzx  ecx,BYTE PTR [rbp-0x29]
    27e9:	48 8b 75 e0          	mov    rsi,QWORD PTR [rbp-0x20]
    27ed:	48 63 d0             	movsxd rdx,eax
    27f0:	48 89 d0             	mov    rax,rdx
    27f3:	48 c1 e0 02          	shl    rax,0x2
    27f7:	48 01 d0             	add    rax,rdx
    27fa:	48 c1 e0 03          	shl    rax,0x3
    27fe:	48 01 f0             	add    rax,rsi
    2801:	48 83 c0 20          	add    rax,0x20
    2805:	48 89 08             	mov    QWORD PTR [rax],rcx
    2808:	80 45 d7 01          	add    BYTE PTR [rbp-0x29],0x1
    280c:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    2810:	0f b6 40 08          	movzx  eax,BYTE PTR [rax+0x8]
    2814:	38 45 d7             	cmp    BYTE PTR [rbp-0x29],al
    2817:	72 c8                	jb     27e1 <test_threshold_tree_verify_all_shares_impl+0xfb>
    2819:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
    281d:	48 8b 80 60 01 00 00 	mov    rax,QWORD PTR [rax+0x160]
    2824:	48 83 f8 07          	cmp    rax,0x7
    2828:	76 07                	jbe    2831 <test_threshold_tree_verify_all_shares_impl+0x14b>
    282a:	b8 00 00 00 00       	mov    eax,0x0
    282f:	eb 05                	jmp    2836 <test_threshold_tree_verify_all_shares_impl+0x150>
    2831:	b8 ff ff ff ff       	mov    eax,0xffffffff
    2836:	4c 89 cc             	mov    rsp,r9
    2839:	48 8b 5d e8          	mov    rbx,QWORD PTR [rbp-0x18]
    283d:	64 48 33 1c 25 28 00 	xor    rbx,QWORD PTR fs:0x28
    2844:	00 00 
    2846:	74 05                	je     284d <test_threshold_tree_verify_all_shares_impl+0x167>
    2848:	e8 a3 ee ff ff       	call   16f0 <__stack_chk_fail@plt>
    284d:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
    2851:	c9                   	leave  
    2852:	c3                   	ret    

0000000000002853 <test_threshold_tree_verify_all_shares>:
    2853:	55                   	push   rbp
    2854:	48 89 e5             	mov    rbp,rsp
    2857:	48 83 ec 20          	sub    rsp,0x20
    285b:	48 89 7d e8          	mov    QWORD PTR [rbp-0x18],rdi
    285f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    2863:	48 89 c7             	mov    rdi,rax
    2866:	e8 4a f3 ff ff       	call   1bb5 <threshold_tree_check_complete_structure>
    286b:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
    286e:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
    2872:	74 05                	je     2879 <test_threshold_tree_verify_all_shares+0x26>
    2874:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
    2877:	eb 0f                	jmp    2888 <test_threshold_tree_verify_all_shares+0x35>
    2879:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    287d:	48 8b 00             	mov    rax,QWORD PTR [rax]
    2880:	48 89 c7             	mov    rdi,rax
    2883:	e8 5e fe ff ff       	call   26e6 <test_threshold_tree_verify_all_shares_impl>
    2888:	c9                   	leave  
    2889:	c3                   	ret    

000000000000288a <printHexBytes>:
    288a:	55                   	push   rbp
    288b:	48 89 e5             	mov    rbp,rsp
    288e:	48 83 ec 30          	sub    rsp,0x30
    2892:	48 89 7d e8          	mov    QWORD PTR [rbp-0x18],rdi
    2896:	89 75 e4             	mov    DWORD PTR [rbp-0x1c],esi
    2899:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
    289d:	48 89 4d d0          	mov    QWORD PTR [rbp-0x30],rcx
    28a1:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
    28a5:	75 1e                	jne    28c5 <printHexBytes+0x3b>
    28a7:	48 8b 55 d0          	mov    rdx,QWORD PTR [rbp-0x30]
    28ab:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    28af:	48 89 c6             	mov    rsi,rax
    28b2:	48 8d 3d 82 4f 00 00 	lea    rdi,[rip+0x4f82]        # 783b <PRINT_NULL_POINTER+0x3>
    28b9:	b8 00 00 00 00       	mov    eax,0x0
    28be:	e8 9d eb ff ff       	call   1460 <printf@plt>
    28c3:	eb 7a                	jmp    293f <printHexBytes+0xb5>
    28c5:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    28c9:	48 89 c6             	mov    rsi,rax
    28cc:	48 8d 3d 81 4f 00 00 	lea    rdi,[rip+0x4f81]        # 7854 <PRINT_NULL_POINTER+0x1c>
    28d3:	b8 00 00 00 00       	mov    eax,0x0
    28d8:	e8 83 eb ff ff       	call   1460 <printf@plt>
    28dd:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
    28e4:	eb 27                	jmp    290d <printHexBytes+0x83>
    28e6:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
    28e9:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    28ed:	48 01 d0             	add    rax,rdx
    28f0:	0f b6 00             	movzx  eax,BYTE PTR [rax]
    28f3:	0f b6 c0             	movzx  eax,al
    28f6:	89 c6                	mov    esi,eax
    28f8:	48 8d 3d 58 4f 00 00 	lea    rdi,[rip+0x4f58]        # 7857 <PRINT_NULL_POINTER+0x1f>
    28ff:	b8 00 00 00 00       	mov    eax,0x0
    2904:	e8 57 eb ff ff       	call   1460 <printf@plt>
    2909:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
    290d:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
    2910:	83 e8 01             	sub    eax,0x1
    2913:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
    2916:	72 ce                	jb     28e6 <printHexBytes+0x5c>
    2918:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
    291b:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    291f:	48 01 d0             	add    rax,rdx
    2922:	0f b6 00             	movzx  eax,BYTE PTR [rax]
    2925:	0f b6 c0             	movzx  eax,al
    2928:	48 8b 55 d0          	mov    rdx,QWORD PTR [rbp-0x30]
    292c:	89 c6                	mov    esi,eax
    292e:	48 8d 3d 27 4f 00 00 	lea    rdi,[rip+0x4f27]        # 785c <PRINT_NULL_POINTER+0x24>
    2935:	b8 00 00 00 00       	mov    eax,0x0
    293a:	e8 21 eb ff ff       	call   1460 <printf@plt>
    293f:	c9                   	leave  
    2940:	c3                   	ret    

0000000000002941 <print_subtree_impl>:
    2941:	55                   	push   rbp
    2942:	48 89 e5             	mov    rbp,rsp
    2945:	48 83 ec 20          	sub    rsp,0x20
    2949:	48 89 7d e8          	mov    QWORD PTR [rbp-0x18],rdi
    294d:	89 f0                	mov    eax,esi
    294f:	88 45 e4             	mov    BYTE PTR [rbp-0x1c],al
    2952:	c6 45 fd 00          	mov    BYTE PTR [rbp-0x3],0x0
    2956:	eb 15                	jmp    296d <print_subtree_impl+0x2c>
    2958:	48 8d 3d d5 4e 00 00 	lea    rdi,[rip+0x4ed5]        # 7834 <PRINT_INDENT_STR>
    295f:	b8 00 00 00 00       	mov    eax,0x0
    2964:	e8 f7 ea ff ff       	call   1460 <printf@plt>
    2969:	80 45 fd 01          	add    BYTE PTR [rbp-0x3],0x1
    296d:	0f b6 45 fd          	movzx  eax,BYTE PTR [rbp-0x3]
    2971:	3a 45 e4             	cmp    al,BYTE PTR [rbp-0x1c]
    2974:	72 e2                	jb     2958 <print_subtree_impl+0x17>
    2976:	0f b6 45 e4          	movzx  eax,BYTE PTR [rbp-0x1c]
    297a:	88 45 fe             	mov    BYTE PTR [rbp-0x2],al
    297d:	eb 21                	jmp    29a0 <print_subtree_impl+0x5f>
    297f:	48 8d 15 dd 4e 00 00 	lea    rdx,[rip+0x4edd]        # 7863 <PRINT_NULL_POINTER+0x2b>
    2986:	be 03 00 00 00       	mov    esi,0x3
    298b:	48 8d 3d d2 4e 00 00 	lea    rdi,[rip+0x4ed2]        # 7864 <PRINT_NULL_POINTER+0x2c>
    2992:	b8 00 00 00 00       	mov    eax,0x0
    2997:	e8 c4 ea ff ff       	call   1460 <printf@plt>
    299c:	80 45 fe 01          	add    BYTE PTR [rbp-0x2],0x1
    29a0:	0f b6 05 69 76 20 00 	movzx  eax,BYTE PTR [rip+0x207669]        # 20a010 <print_max_height>
    29a7:	38 45 fe             	cmp    BYTE PTR [rbp-0x2],al
    29aa:	72 d3                	jb     297f <print_subtree_impl+0x3e>
    29ac:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
    29b1:	75 11                	jne    29c4 <print_subtree_impl+0x83>
    29b3:	48 8d 3d 7e 4e 00 00 	lea    rdi,[rip+0x4e7e]        # 7838 <PRINT_NULL_POINTER>
    29ba:	e8 51 eb ff ff       	call   1510 <puts@plt>
    29bf:	e9 98 00 00 00       	jmp    2a5c <print_subtree_impl+0x11b>
    29c4:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    29c8:	0f b6 40 08          	movzx  eax,BYTE PTR [rax+0x8]
    29cc:	0f b6 c8             	movzx  ecx,al
    29cf:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    29d3:	0f b6 40 09          	movzx  eax,BYTE PTR [rax+0x9]
    29d7:	0f b6 d0             	movzx  edx,al
    29da:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    29de:	48 8b 00             	mov    rax,QWORD PTR [rax]
    29e1:	48 89 c6             	mov    rsi,rax
    29e4:	48 8d 3d 7d 4e 00 00 	lea    rdi,[rip+0x4e7d]        # 7868 <PRINT_NULL_POINTER+0x30>
    29eb:	b8 00 00 00 00       	mov    eax,0x0
    29f0:	e8 6b ea ff ff       	call   1460 <printf@plt>
    29f5:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    29f9:	48 83 c0 0a          	add    rax,0xa
    29fd:	48 8d 0d 75 4e 00 00 	lea    rcx,[rip+0x4e75]        # 7879 <PRINT_NULL_POINTER+0x41>
    2a04:	48 8d 15 70 4e 00 00 	lea    rdx,[rip+0x4e70]        # 787b <PRINT_NULL_POINTER+0x43>
    2a0b:	be 20 00 00 00       	mov    esi,0x20
    2a10:	48 89 c7             	mov    rdi,rax
    2a13:	e8 72 fe ff ff       	call   288a <printHexBytes>
    2a18:	c6 45 ff 00          	mov    BYTE PTR [rbp-0x1],0x0
    2a1c:	eb 31                	jmp    2a4f <print_subtree_impl+0x10e>
    2a1e:	0f b6 45 e4          	movzx  eax,BYTE PTR [rbp-0x1c]
    2a22:	83 c0 01             	add    eax,0x1
    2a25:	0f b6 d0             	movzx  edx,al
    2a28:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    2a2c:	48 8b 80 80 00 00 00 	mov    rax,QWORD PTR [rax+0x80]
    2a33:	0f b6 4d ff          	movzx  ecx,BYTE PTR [rbp-0x1]
    2a37:	48 c1 e1 03          	shl    rcx,0x3
    2a3b:	48 01 c8             	add    rax,rcx
    2a3e:	48 8b 00             	mov    rax,QWORD PTR [rax]
    2a41:	89 d6                	mov    esi,edx
    2a43:	48 89 c7             	mov    rdi,rax
    2a46:	e8 f6 fe ff ff       	call   2941 <print_subtree_impl>
    2a4b:	80 45 ff 01          	add    BYTE PTR [rbp-0x1],0x1
    2a4f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    2a53:	0f b6 40 08          	movzx  eax,BYTE PTR [rax+0x8]
    2a57:	38 45 ff             	cmp    BYTE PTR [rbp-0x1],al
    2a5a:	72 c2                	jb     2a1e <print_subtree_impl+0xdd>
    2a5c:	90                   	nop
    2a5d:	c9                   	leave  
    2a5e:	c3                   	ret    

0000000000002a5f <print_threshold_tree>:
    2a5f:	55                   	push   rbp
    2a60:	48 89 e5             	mov    rbp,rsp
    2a63:	48 83 ec 20          	sub    rsp,0x20
    2a67:	48 89 7d f8          	mov    QWORD PTR [rbp-0x8],rdi
    2a6b:	48 89 75 f0          	mov    QWORD PTR [rbp-0x10],rsi
    2a6f:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
    2a73:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    2a77:	48 89 c7             	mov    rdi,rax
    2a7a:	e8 91 ea ff ff       	call   1510 <puts@plt>
    2a7f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    2a83:	48 8b 00             	mov    rax,QWORD PTR [rax]
    2a86:	be 00 00 00 00       	mov    esi,0x0
    2a8b:	48 89 c7             	mov    rdi,rax
    2a8e:	e8 ae fe ff ff       	call   2941 <print_subtree_impl>
    2a93:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    2a97:	48 89 c6             	mov    rsi,rax
    2a9a:	48 8d 3d b3 4d 00 00 	lea    rdi,[rip+0x4db3]        # 7854 <PRINT_NULL_POINTER+0x1c>
    2aa1:	b8 00 00 00 00       	mov    eax,0x0
    2aa6:	e8 b5 e9 ff ff       	call   1460 <printf@plt>
    2aab:	90                   	nop
    2aac:	c9                   	leave  
    2aad:	c3                   	ret    

0000000000002aae <empty_tree_lookup>:
    2aae:	55                   	push   rbp
    2aaf:	48 89 e5             	mov    rbp,rsp
    2ab2:	48 83 ec 20          	sub    rsp,0x20
    2ab6:	48 89 7d e8          	mov    QWORD PTR [rbp-0x18],rdi
    2aba:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    2ac1:	00 00 
    2ac3:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    2ac7:	31 c0                	xor    eax,eax
    2ac9:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
    2ad0:	00 
    2ad1:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    2ad5:	48 89 c7             	mov    rdi,rax
    2ad8:	e8 d8 f0 ff ff       	call   1bb5 <threshold_tree_check_complete_structure>
    2add:	83 f8 f6             	cmp    eax,0xfffffff6
    2ae0:	74 1f                	je     2b01 <empty_tree_lookup+0x53>
    2ae2:	48 8d 0d 27 60 00 00 	lea    rcx,[rip+0x6027]        # 8b10 <__PRETTY_FUNCTION__.3418>
    2ae9:	ba 4e 00 00 00       	mov    edx,0x4e
    2aee:	48 8d 35 a7 4d 00 00 	lea    rsi,[rip+0x4da7]        # 789c <path_0_1_0_0+0x4>
    2af5:	48 8d 3d b4 4d 00 00 	lea    rdi,[rip+0x4db4]        # 78b0 <path_0_1_0_0+0x18>
    2afc:	e8 1f ea ff ff       	call   1520 <__assert_fail@plt>
    2b01:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    2b05:	ba 00 00 00 00       	mov    edx,0x0
    2b0a:	be 38 15 00 00       	mov    esi,0x1538
    2b0f:	48 89 c7             	mov    rdi,rax
    2b12:	e8 77 f2 ff ff       	call   1d8e <threshold_tree_get_node_by_id>
    2b17:	83 f8 fa             	cmp    eax,0xfffffffa
    2b1a:	74 1f                	je     2b3b <empty_tree_lookup+0x8d>
    2b1c:	48 8d 0d ed 5f 00 00 	lea    rcx,[rip+0x5fed]        # 8b10 <__PRETTY_FUNCTION__.3418>
    2b23:	ba 50 00 00 00       	mov    edx,0x50
    2b28:	48 8d 35 6d 4d 00 00 	lea    rsi,[rip+0x4d6d]        # 789c <path_0_1_0_0+0x4>
    2b2f:	48 8d 3d da 4d 00 00 	lea    rdi,[rip+0x4dda]        # 7910 <path_0_1_0_0+0x78>
    2b36:	e8 e5 e9 ff ff       	call   1520 <__assert_fail@plt>
    2b3b:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
    2b3f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    2b43:	be 38 15 00 00       	mov    esi,0x1538
    2b48:	48 89 c7             	mov    rdi,rax
    2b4b:	e8 3e f2 ff ff       	call   1d8e <threshold_tree_get_node_by_id>
    2b50:	83 f8 fa             	cmp    eax,0xfffffffa
    2b53:	74 1f                	je     2b74 <empty_tree_lookup+0xc6>
    2b55:	48 8d 0d b4 5f 00 00 	lea    rcx,[rip+0x5fb4]        # 8b10 <__PRETTY_FUNCTION__.3418>
    2b5c:	ba 51 00 00 00       	mov    edx,0x51
    2b61:	48 8d 35 34 4d 00 00 	lea    rsi,[rip+0x4d34]        # 789c <path_0_1_0_0+0x4>
    2b68:	48 8d 3d f9 4d 00 00 	lea    rdi,[rip+0x4df9]        # 7968 <path_0_1_0_0+0xd0>
    2b6f:	e8 ac e9 ff ff       	call   1520 <__assert_fail@plt>
    2b74:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    2b78:	48 85 c0             	test   rax,rax
    2b7b:	74 1f                	je     2b9c <empty_tree_lookup+0xee>
    2b7d:	48 8d 0d 8c 5f 00 00 	lea    rcx,[rip+0x5f8c]        # 8b10 <__PRETTY_FUNCTION__.3418>
    2b84:	ba 51 00 00 00       	mov    edx,0x51
    2b89:	48 8d 35 0c 4d 00 00 	lea    rsi,[rip+0x4d0c]        # 789c <path_0_1_0_0+0x4>
    2b90:	48 8d 3d 29 4e 00 00 	lea    rdi,[rip+0x4e29]        # 79c0 <path_0_1_0_0+0x128>
    2b97:	e8 84 e9 ff ff       	call   1520 <__assert_fail@plt>
    2b9c:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    2ba0:	b9 00 00 00 00       	mov    ecx,0x0
    2ba5:	ba 00 00 00 00       	mov    edx,0x0
    2baa:	48 8d 35 d3 4c 00 00 	lea    rsi,[rip+0x4cd3]        # 7884 <path_0>
    2bb1:	48 89 c7             	mov    rdi,rax
    2bb4:	e8 b8 f0 ff ff       	call   1c71 <threshold_tree_get_node_by_path>
    2bb9:	83 f8 fe             	cmp    eax,0xfffffffe
    2bbc:	74 1f                	je     2bdd <empty_tree_lookup+0x12f>
    2bbe:	48 8d 0d 4b 5f 00 00 	lea    rcx,[rip+0x5f4b]        # 8b10 <__PRETTY_FUNCTION__.3418>
    2bc5:	ba 53 00 00 00       	mov    edx,0x53
    2bca:	48 8d 35 cb 4c 00 00 	lea    rsi,[rip+0x4ccb]        # 789c <path_0_1_0_0+0x4>
    2bd1:	48 8d 3d 08 4e 00 00 	lea    rdi,[rip+0x4e08]        # 79e0 <path_0_1_0_0+0x148>
    2bd8:	e8 43 e9 ff ff       	call   1520 <__assert_fail@plt>
    2bdd:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    2be1:	b9 00 00 00 00       	mov    ecx,0x0
    2be6:	ba 01 00 00 00       	mov    edx,0x1
    2beb:	48 8d 35 92 4c 00 00 	lea    rsi,[rip+0x4c92]        # 7884 <path_0>
    2bf2:	48 89 c7             	mov    rdi,rax
    2bf5:	e8 77 f0 ff ff       	call   1c71 <threshold_tree_get_node_by_path>
    2bfa:	83 f8 fe             	cmp    eax,0xfffffffe
    2bfd:	74 1f                	je     2c1e <empty_tree_lookup+0x170>
    2bff:	48 8d 0d 0a 5f 00 00 	lea    rcx,[rip+0x5f0a]        # 8b10 <__PRETTY_FUNCTION__.3418>
    2c06:	ba 54 00 00 00       	mov    edx,0x54
    2c0b:	48 8d 35 8a 4c 00 00 	lea    rsi,[rip+0x4c8a]        # 789c <path_0_1_0_0+0x4>
    2c12:	48 8d 3d 2f 4e 00 00 	lea    rdi,[rip+0x4e2f]        # 7a48 <path_0_1_0_0+0x1b0>
    2c19:	e8 02 e9 ff ff       	call   1520 <__assert_fail@plt>
    2c1e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    2c22:	b9 00 00 00 00       	mov    ecx,0x0
    2c27:	ba 01 00 00 00       	mov    edx,0x1
    2c2c:	48 8d 35 54 4c 00 00 	lea    rsi,[rip+0x4c54]        # 7887 <path_3>
    2c33:	48 89 c7             	mov    rdi,rax
    2c36:	e8 36 f0 ff ff       	call   1c71 <threshold_tree_get_node_by_path>
    2c3b:	83 f8 fe             	cmp    eax,0xfffffffe
    2c3e:	74 1f                	je     2c5f <empty_tree_lookup+0x1b1>
    2c40:	48 8d 0d c9 5e 00 00 	lea    rcx,[rip+0x5ec9]        # 8b10 <__PRETTY_FUNCTION__.3418>
    2c47:	ba 55 00 00 00       	mov    edx,0x55
    2c4c:	48 8d 35 49 4c 00 00 	lea    rsi,[rip+0x4c49]        # 789c <path_0_1_0_0+0x4>
    2c53:	48 8d 3d 56 4e 00 00 	lea    rdi,[rip+0x4e56]        # 7ab0 <path_0_1_0_0+0x218>
    2c5a:	e8 c1 e8 ff ff       	call   1520 <__assert_fail@plt>
    2c5f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    2c63:	b9 00 00 00 00       	mov    ecx,0x0
    2c68:	ba 02 00 00 00       	mov    edx,0x2
    2c6d:	48 8d 35 1c 4c 00 00 	lea    rsi,[rip+0x4c1c]        # 7890 <path_1_1>
    2c74:	48 89 c7             	mov    rdi,rax
    2c77:	e8 f5 ef ff ff       	call   1c71 <threshold_tree_get_node_by_path>
    2c7c:	83 f8 fe             	cmp    eax,0xfffffffe
    2c7f:	74 1f                	je     2ca0 <empty_tree_lookup+0x1f2>
    2c81:	48 8d 0d 88 5e 00 00 	lea    rcx,[rip+0x5e88]        # 8b10 <__PRETTY_FUNCTION__.3418>
    2c88:	ba 56 00 00 00       	mov    edx,0x56
    2c8d:	48 8d 35 08 4c 00 00 	lea    rsi,[rip+0x4c08]        # 789c <path_0_1_0_0+0x4>
    2c94:	48 8d 3d 7d 4e 00 00 	lea    rdi,[rip+0x4e7d]        # 7b18 <path_0_1_0_0+0x280>
    2c9b:	e8 80 e8 ff ff       	call   1520 <__assert_fail@plt>
    2ca0:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
    2ca4:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    2ca8:	48 89 d1             	mov    rcx,rdx
    2cab:	ba 00 00 00 00       	mov    edx,0x0
    2cb0:	48 8d 35 cd 4b 00 00 	lea    rsi,[rip+0x4bcd]        # 7884 <path_0>
    2cb7:	48 89 c7             	mov    rdi,rax
    2cba:	e8 b2 ef ff ff       	call   1c71 <threshold_tree_get_node_by_path>
    2cbf:	83 f8 fe             	cmp    eax,0xfffffffe
    2cc2:	74 1f                	je     2ce3 <empty_tree_lookup+0x235>
    2cc4:	48 8d 0d 45 5e 00 00 	lea    rcx,[rip+0x5e45]        # 8b10 <__PRETTY_FUNCTION__.3418>
    2ccb:	ba 58 00 00 00       	mov    edx,0x58
    2cd0:	48 8d 35 c5 4b 00 00 	lea    rsi,[rip+0x4bc5]        # 789c <path_0_1_0_0+0x4>
    2cd7:	48 8d 3d a2 4e 00 00 	lea    rdi,[rip+0x4ea2]        # 7b80 <path_0_1_0_0+0x2e8>
    2cde:	e8 3d e8 ff ff       	call   1520 <__assert_fail@plt>
    2ce3:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    2ce7:	48 85 c0             	test   rax,rax
    2cea:	74 1f                	je     2d0b <empty_tree_lookup+0x25d>
    2cec:	48 8d 0d 1d 5e 00 00 	lea    rcx,[rip+0x5e1d]        # 8b10 <__PRETTY_FUNCTION__.3418>
    2cf3:	ba 58 00 00 00       	mov    edx,0x58
    2cf8:	48 8d 35 9d 4b 00 00 	lea    rsi,[rip+0x4b9d]        # 789c <path_0_1_0_0+0x4>
    2cff:	48 8d 3d ba 4c 00 00 	lea    rdi,[rip+0x4cba]        # 79c0 <path_0_1_0_0+0x128>
    2d06:	e8 15 e8 ff ff       	call   1520 <__assert_fail@plt>
    2d0b:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
    2d0f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    2d13:	48 89 d1             	mov    rcx,rdx
    2d16:	ba 01 00 00 00       	mov    edx,0x1
    2d1b:	48 8d 35 62 4b 00 00 	lea    rsi,[rip+0x4b62]        # 7884 <path_0>
    2d22:	48 89 c7             	mov    rdi,rax
    2d25:	e8 47 ef ff ff       	call   1c71 <threshold_tree_get_node_by_path>
    2d2a:	83 f8 fe             	cmp    eax,0xfffffffe
    2d2d:	74 1f                	je     2d4e <empty_tree_lookup+0x2a0>
    2d2f:	48 8d 0d da 5d 00 00 	lea    rcx,[rip+0x5dda]        # 8b10 <__PRETTY_FUNCTION__.3418>
    2d36:	ba 59 00 00 00       	mov    edx,0x59
    2d3b:	48 8d 35 5a 4b 00 00 	lea    rsi,[rip+0x4b5a]        # 789c <path_0_1_0_0+0x4>
    2d42:	48 8d 3d 9f 4e 00 00 	lea    rdi,[rip+0x4e9f]        # 7be8 <path_0_1_0_0+0x350>
    2d49:	e8 d2 e7 ff ff       	call   1520 <__assert_fail@plt>
    2d4e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    2d52:	48 85 c0             	test   rax,rax
    2d55:	74 1f                	je     2d76 <empty_tree_lookup+0x2c8>
    2d57:	48 8d 0d b2 5d 00 00 	lea    rcx,[rip+0x5db2]        # 8b10 <__PRETTY_FUNCTION__.3418>
    2d5e:	ba 59 00 00 00       	mov    edx,0x59
    2d63:	48 8d 35 32 4b 00 00 	lea    rsi,[rip+0x4b32]        # 789c <path_0_1_0_0+0x4>
    2d6a:	48 8d 3d 4f 4c 00 00 	lea    rdi,[rip+0x4c4f]        # 79c0 <path_0_1_0_0+0x128>
    2d71:	e8 aa e7 ff ff       	call   1520 <__assert_fail@plt>
    2d76:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
    2d7a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    2d7e:	48 89 d1             	mov    rcx,rdx
    2d81:	ba 01 00 00 00       	mov    edx,0x1
    2d86:	48 8d 35 fa 4a 00 00 	lea    rsi,[rip+0x4afa]        # 7887 <path_3>
    2d8d:	48 89 c7             	mov    rdi,rax
    2d90:	e8 dc ee ff ff       	call   1c71 <threshold_tree_get_node_by_path>
    2d95:	83 f8 fe             	cmp    eax,0xfffffffe
    2d98:	74 1f                	je     2db9 <empty_tree_lookup+0x30b>
    2d9a:	48 8d 0d 6f 5d 00 00 	lea    rcx,[rip+0x5d6f]        # 8b10 <__PRETTY_FUNCTION__.3418>
    2da1:	ba 5a 00 00 00       	mov    edx,0x5a
    2da6:	48 8d 35 ef 4a 00 00 	lea    rsi,[rip+0x4aef]        # 789c <path_0_1_0_0+0x4>
    2dad:	48 8d 3d 9c 4e 00 00 	lea    rdi,[rip+0x4e9c]        # 7c50 <path_0_1_0_0+0x3b8>
    2db4:	e8 67 e7 ff ff       	call   1520 <__assert_fail@plt>
    2db9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    2dbd:	48 85 c0             	test   rax,rax
    2dc0:	74 1f                	je     2de1 <empty_tree_lookup+0x333>
    2dc2:	48 8d 0d 47 5d 00 00 	lea    rcx,[rip+0x5d47]        # 8b10 <__PRETTY_FUNCTION__.3418>
    2dc9:	ba 5a 00 00 00       	mov    edx,0x5a
    2dce:	48 8d 35 c7 4a 00 00 	lea    rsi,[rip+0x4ac7]        # 789c <path_0_1_0_0+0x4>
    2dd5:	48 8d 3d e4 4b 00 00 	lea    rdi,[rip+0x4be4]        # 79c0 <path_0_1_0_0+0x128>
    2ddc:	e8 3f e7 ff ff       	call   1520 <__assert_fail@plt>
    2de1:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
    2de5:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    2de9:	48 89 d1             	mov    rcx,rdx
    2dec:	ba 02 00 00 00       	mov    edx,0x2
    2df1:	48 8d 35 98 4a 00 00 	lea    rsi,[rip+0x4a98]        # 7890 <path_1_1>
    2df8:	48 89 c7             	mov    rdi,rax
    2dfb:	e8 71 ee ff ff       	call   1c71 <threshold_tree_get_node_by_path>
    2e00:	83 f8 fe             	cmp    eax,0xfffffffe
    2e03:	74 1f                	je     2e24 <empty_tree_lookup+0x376>
    2e05:	48 8d 0d 04 5d 00 00 	lea    rcx,[rip+0x5d04]        # 8b10 <__PRETTY_FUNCTION__.3418>
    2e0c:	ba 5b 00 00 00       	mov    edx,0x5b
    2e11:	48 8d 35 84 4a 00 00 	lea    rsi,[rip+0x4a84]        # 789c <path_0_1_0_0+0x4>
    2e18:	48 8d 3d 99 4e 00 00 	lea    rdi,[rip+0x4e99]        # 7cb8 <path_0_1_0_0+0x420>
    2e1f:	e8 fc e6 ff ff       	call   1520 <__assert_fail@plt>
    2e24:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    2e28:	48 85 c0             	test   rax,rax
    2e2b:	74 1f                	je     2e4c <empty_tree_lookup+0x39e>
    2e2d:	48 8d 0d dc 5c 00 00 	lea    rcx,[rip+0x5cdc]        # 8b10 <__PRETTY_FUNCTION__.3418>
    2e34:	ba 5b 00 00 00       	mov    edx,0x5b
    2e39:	48 8d 35 5c 4a 00 00 	lea    rsi,[rip+0x4a5c]        # 789c <path_0_1_0_0+0x4>
    2e40:	48 8d 3d 79 4b 00 00 	lea    rdi,[rip+0x4b79]        # 79c0 <path_0_1_0_0+0x128>
    2e47:	e8 d4 e6 ff ff       	call   1520 <__assert_fail@plt>
    2e4c:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    2e50:	48 89 c7             	mov    rdi,rax
    2e53:	e8 5d ed ff ff       	call   1bb5 <threshold_tree_check_complete_structure>
    2e58:	85 c0                	test   eax,eax
    2e5a:	74 1f                	je     2e7b <empty_tree_lookup+0x3cd>
    2e5c:	48 8d 0d ad 5c 00 00 	lea    rcx,[rip+0x5cad]        # 8b10 <__PRETTY_FUNCTION__.3418>
    2e63:	ba 5d 00 00 00       	mov    edx,0x5d
    2e68:	48 8d 35 2d 4a 00 00 	lea    rsi,[rip+0x4a2d]        # 789c <path_0_1_0_0+0x4>
    2e6f:	48 8d 3d aa 4e 00 00 	lea    rdi,[rip+0x4eaa]        # 7d20 <path_0_1_0_0+0x488>
    2e76:	e8 a5 e6 ff ff       	call   1520 <__assert_fail@plt>
    2e7b:	90                   	nop
    2e7c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    2e80:	64 48 33 04 25 28 00 	xor    rax,QWORD PTR fs:0x28
    2e87:	00 00 
    2e89:	74 05                	je     2e90 <empty_tree_lookup+0x3e2>
    2e8b:	e8 60 e8 ff ff       	call   16f0 <__stack_chk_fail@plt>
    2e90:	c9                   	leave  
    2e91:	c3                   	ret    

0000000000002e92 <build_a_tree>:
    2e92:	55                   	push   rbp
    2e93:	48 89 e5             	mov    rbp,rsp
    2e96:	48 83 ec 10          	sub    rsp,0x10
    2e9a:	48 89 7d f8          	mov    QWORD PTR [rbp-0x8],rdi
    2e9e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    2ea2:	41 b9 01 00 00 00    	mov    r9d,0x1
    2ea8:	41 b8 02 00 00 00    	mov    r8d,0x2
    2eae:	b9 63 00 00 00       	mov    ecx,0x63
    2eb3:	ba 01 00 00 00       	mov    edx,0x1
    2eb8:	48 8d 35 c5 49 00 00 	lea    rsi,[rip+0x49c5]        # 7884 <path_0>
    2ebf:	48 89 c7             	mov    rdi,rax
    2ec2:	e8 48 ef ff ff       	call   1e0f <threshold_tree_add_node>
    2ec7:	83 f8 fe             	cmp    eax,0xfffffffe
    2eca:	74 1f                	je     2eeb <build_a_tree+0x59>
    2ecc:	48 8d 0d 55 5c 00 00 	lea    rcx,[rip+0x5c55]        # 8b28 <__PRETTY_FUNCTION__.3422>
    2ed3:	ba 61 00 00 00       	mov    edx,0x61
    2ed8:	48 8d 35 bd 49 00 00 	lea    rsi,[rip+0x49bd]        # 789c <path_0_1_0_0+0x4>
    2edf:	48 8d 3d 8a 4e 00 00 	lea    rdi,[rip+0x4e8a]        # 7d70 <path_0_1_0_0+0x4d8>
    2ee6:	e8 35 e6 ff ff       	call   1520 <__assert_fail@plt>
    2eeb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    2eef:	48 89 c7             	mov    rdi,rax
    2ef2:	e8 be ec ff ff       	call   1bb5 <threshold_tree_check_complete_structure>
    2ef7:	83 f8 f6             	cmp    eax,0xfffffff6
    2efa:	74 1f                	je     2f1b <build_a_tree+0x89>
    2efc:	48 8d 0d 25 5c 00 00 	lea    rcx,[rip+0x5c25]        # 8b28 <__PRETTY_FUNCTION__.3422>
    2f03:	ba 63 00 00 00       	mov    edx,0x63
    2f08:	48 8d 35 8d 49 00 00 	lea    rsi,[rip+0x498d]        # 789c <path_0_1_0_0+0x4>
    2f0f:	48 8d 3d 9a 49 00 00 	lea    rdi,[rip+0x499a]        # 78b0 <path_0_1_0_0+0x18>
    2f16:	e8 05 e6 ff ff       	call   1520 <__assert_fail@plt>
    2f1b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    2f1f:	41 b9 02 00 00 00    	mov    r9d,0x2
    2f25:	41 b8 01 00 00 00    	mov    r8d,0x1
    2f2b:	b9 63 00 00 00       	mov    ecx,0x63
    2f30:	ba 00 00 00 00       	mov    edx,0x0
    2f35:	48 8d 35 48 49 00 00 	lea    rsi,[rip+0x4948]        # 7884 <path_0>
    2f3c:	48 89 c7             	mov    rdi,rax
    2f3f:	e8 cb ee ff ff       	call   1e0f <threshold_tree_add_node>
    2f44:	83 f8 fd             	cmp    eax,0xfffffffd
    2f47:	74 1f                	je     2f68 <build_a_tree+0xd6>
    2f49:	48 8d 0d d8 5b 00 00 	lea    rcx,[rip+0x5bd8]        # 8b28 <__PRETTY_FUNCTION__.3422>
    2f50:	ba 65 00 00 00       	mov    edx,0x65
    2f55:	48 8d 35 40 49 00 00 	lea    rsi,[rip+0x4940]        # 789c <path_0_1_0_0+0x4>
    2f5c:	48 8d 3d 65 4e 00 00 	lea    rdi,[rip+0x4e65]        # 7dc8 <path_0_1_0_0+0x530>
    2f63:	e8 b8 e5 ff ff       	call   1520 <__assert_fail@plt>
    2f68:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    2f6c:	41 b9 00 00 00 00    	mov    r9d,0x0
    2f72:	41 b8 01 00 00 00    	mov    r8d,0x1
    2f78:	b9 63 00 00 00       	mov    ecx,0x63
    2f7d:	ba 00 00 00 00       	mov    edx,0x0
    2f82:	48 8d 35 fb 48 00 00 	lea    rsi,[rip+0x48fb]        # 7884 <path_0>
    2f89:	48 89 c7             	mov    rdi,rax
    2f8c:	e8 7e ee ff ff       	call   1e0f <threshold_tree_add_node>
    2f91:	83 f8 fd             	cmp    eax,0xfffffffd
    2f94:	74 1f                	je     2fb5 <build_a_tree+0x123>
    2f96:	48 8d 0d 8b 5b 00 00 	lea    rcx,[rip+0x5b8b]        # 8b28 <__PRETTY_FUNCTION__.3422>
    2f9d:	ba 66 00 00 00       	mov    edx,0x66
    2fa2:	48 8d 35 f3 48 00 00 	lea    rsi,[rip+0x48f3]        # 789c <path_0_1_0_0+0x4>
    2fa9:	48 8d 3d 78 4e 00 00 	lea    rdi,[rip+0x4e78]        # 7e28 <path_0_1_0_0+0x590>
    2fb0:	e8 6b e5 ff ff       	call   1520 <__assert_fail@plt>
    2fb5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    2fb9:	41 b9 02 00 00 00    	mov    r9d,0x2
    2fbf:	41 b8 03 00 00 00    	mov    r8d,0x3
    2fc5:	b9 01 00 00 00       	mov    ecx,0x1
    2fca:	ba 00 00 00 00       	mov    edx,0x0
    2fcf:	48 8d 35 ae 48 00 00 	lea    rsi,[rip+0x48ae]        # 7884 <path_0>
    2fd6:	48 89 c7             	mov    rdi,rax
    2fd9:	e8 31 ee ff ff       	call   1e0f <threshold_tree_add_node>
    2fde:	85 c0                	test   eax,eax
    2fe0:	74 1f                	je     3001 <build_a_tree+0x16f>
    2fe2:	48 8d 0d 3f 5b 00 00 	lea    rcx,[rip+0x5b3f]        # 8b28 <__PRETTY_FUNCTION__.3422>
    2fe9:	ba 67 00 00 00       	mov    edx,0x67
    2fee:	48 8d 35 a7 48 00 00 	lea    rsi,[rip+0x48a7]        # 789c <path_0_1_0_0+0x4>
    2ff5:	48 8d 3d 8c 4e 00 00 	lea    rdi,[rip+0x4e8c]        # 7e88 <path_0_1_0_0+0x5f0>
    2ffc:	e8 1f e5 ff ff       	call   1520 <__assert_fail@plt>
    3001:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    3005:	41 b9 02 00 00 00    	mov    r9d,0x2
    300b:	41 b8 03 00 00 00    	mov    r8d,0x3
    3011:	b9 63 00 00 00       	mov    ecx,0x63
    3016:	ba 00 00 00 00       	mov    edx,0x0
    301b:	48 8d 35 62 48 00 00 	lea    rsi,[rip+0x4862]        # 7884 <path_0>
    3022:	48 89 c7             	mov    rdi,rax
    3025:	e8 e5 ed ff ff       	call   1e0f <threshold_tree_add_node>
    302a:	83 f8 fe             	cmp    eax,0xfffffffe
    302d:	74 1f                	je     304e <build_a_tree+0x1bc>
    302f:	48 8d 0d f2 5a 00 00 	lea    rcx,[rip+0x5af2]        # 8b28 <__PRETTY_FUNCTION__.3422>
    3036:	ba 68 00 00 00       	mov    edx,0x68
    303b:	48 8d 35 5a 48 00 00 	lea    rsi,[rip+0x485a]        # 789c <path_0_1_0_0+0x4>
    3042:	48 8d 3d 8f 4e 00 00 	lea    rdi,[rip+0x4e8f]        # 7ed8 <path_0_1_0_0+0x640>
    3049:	e8 d2 e4 ff ff       	call   1520 <__assert_fail@plt>
    304e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    3052:	48 89 c7             	mov    rdi,rax
    3055:	e8 5b eb ff ff       	call   1bb5 <threshold_tree_check_complete_structure>
    305a:	83 f8 f6             	cmp    eax,0xfffffff6
    305d:	74 1f                	je     307e <build_a_tree+0x1ec>
    305f:	48 8d 0d c2 5a 00 00 	lea    rcx,[rip+0x5ac2]        # 8b28 <__PRETTY_FUNCTION__.3422>
    3066:	ba 6a 00 00 00       	mov    edx,0x6a
    306b:	48 8d 35 2a 48 00 00 	lea    rsi,[rip+0x482a]        # 789c <path_0_1_0_0+0x4>
    3072:	48 8d 3d 37 48 00 00 	lea    rdi,[rip+0x4837]        # 78b0 <path_0_1_0_0+0x18>
    3079:	e8 a2 e4 ff ff       	call   1520 <__assert_fail@plt>
    307e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    3082:	41 b9 01 00 00 00    	mov    r9d,0x1
    3088:	41 b8 01 00 00 00    	mov    r8d,0x1
    308e:	b9 0b 00 00 00       	mov    ecx,0xb
    3093:	ba 01 00 00 00       	mov    edx,0x1
    3098:	48 8d 35 e6 47 00 00 	lea    rsi,[rip+0x47e6]        # 7885 <path_1>
    309f:	48 89 c7             	mov    rdi,rax
    30a2:	e8 68 ed ff ff       	call   1e0f <threshold_tree_add_node>
    30a7:	85 c0                	test   eax,eax
    30a9:	74 1f                	je     30ca <build_a_tree+0x238>
    30ab:	48 8d 0d 76 5a 00 00 	lea    rcx,[rip+0x5a76]        # 8b28 <__PRETTY_FUNCTION__.3422>
    30b2:	ba 6c 00 00 00       	mov    edx,0x6c
    30b7:	48 8d 35 de 47 00 00 	lea    rsi,[rip+0x47de]        # 789c <path_0_1_0_0+0x4>
    30be:	48 8d 3d 6b 4e 00 00 	lea    rdi,[rip+0x4e6b]        # 7f30 <path_0_1_0_0+0x698>
    30c5:	e8 56 e4 ff ff       	call   1520 <__assert_fail@plt>
    30ca:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    30ce:	41 b9 02 00 00 00    	mov    r9d,0x2
    30d4:	41 b8 02 00 00 00    	mov    r8d,0x2
    30da:	b9 63 00 00 00       	mov    ecx,0x63
    30df:	ba 01 00 00 00       	mov    edx,0x1
    30e4:	48 8d 35 9a 47 00 00 	lea    rsi,[rip+0x479a]        # 7885 <path_1>
    30eb:	48 89 c7             	mov    rdi,rax
    30ee:	e8 1c ed ff ff       	call   1e0f <threshold_tree_add_node>
    30f3:	83 f8 fe             	cmp    eax,0xfffffffe
    30f6:	74 1f                	je     3117 <build_a_tree+0x285>
    30f8:	48 8d 0d 29 5a 00 00 	lea    rcx,[rip+0x5a29]        # 8b28 <__PRETTY_FUNCTION__.3422>
    30ff:	ba 6d 00 00 00       	mov    edx,0x6d
    3104:	48 8d 35 91 47 00 00 	lea    rsi,[rip+0x4791]        # 789c <path_0_1_0_0+0x4>
    310b:	48 8d 3d 76 4e 00 00 	lea    rdi,[rip+0x4e76]        # 7f88 <path_0_1_0_0+0x6f0>
    3112:	e8 09 e4 ff ff       	call   1520 <__assert_fail@plt>
    3117:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    311b:	41 b9 03 00 00 00    	mov    r9d,0x3
    3121:	41 b8 03 00 00 00    	mov    r8d,0x3
    3127:	b9 63 00 00 00       	mov    ecx,0x63
    312c:	ba 02 00 00 00       	mov    edx,0x2
    3131:	48 8d 35 58 47 00 00 	lea    rsi,[rip+0x4758]        # 7890 <path_1_1>
    3138:	48 89 c7             	mov    rdi,rax
    313b:	e8 cf ec ff ff       	call   1e0f <threshold_tree_add_node>
    3140:	83 f8 fe             	cmp    eax,0xfffffffe
    3143:	74 1f                	je     3164 <build_a_tree+0x2d2>
    3145:	48 8d 0d dc 59 00 00 	lea    rcx,[rip+0x59dc]        # 8b28 <__PRETTY_FUNCTION__.3422>
    314c:	ba 6e 00 00 00       	mov    edx,0x6e
    3151:	48 8d 35 44 47 00 00 	lea    rsi,[rip+0x4744]        # 789c <path_0_1_0_0+0x4>
    3158:	48 8d 3d 81 4e 00 00 	lea    rdi,[rip+0x4e81]        # 7fe0 <path_0_1_0_0+0x748>
    315f:	e8 bc e3 ff ff       	call   1520 <__assert_fail@plt>
    3164:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    3168:	41 b9 00 00 00 00    	mov    r9d,0x0
    316e:	41 b8 00 00 00 00    	mov    r8d,0x0
    3174:	b9 6e 00 00 00       	mov    ecx,0x6e
    3179:	ba 02 00 00 00       	mov    edx,0x2
    317e:	48 8d 35 09 47 00 00 	lea    rsi,[rip+0x4709]        # 788e <path_1_0>
    3185:	48 89 c7             	mov    rdi,rax
    3188:	e8 82 ec ff ff       	call   1e0f <threshold_tree_add_node>
    318d:	85 c0                	test   eax,eax
    318f:	74 1f                	je     31b0 <build_a_tree+0x31e>
    3191:	48 8d 0d 90 59 00 00 	lea    rcx,[rip+0x5990]        # 8b28 <__PRETTY_FUNCTION__.3422>
    3198:	ba 6f 00 00 00       	mov    edx,0x6f
    319d:	48 8d 35 f8 46 00 00 	lea    rsi,[rip+0x46f8]        # 789c <path_0_1_0_0+0x4>
    31a4:	48 8d 3d 8d 4e 00 00 	lea    rdi,[rip+0x4e8d]        # 8038 <path_0_1_0_0+0x7a0>
    31ab:	e8 70 e3 ff ff       	call   1520 <__assert_fail@plt>
    31b0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    31b4:	48 89 c7             	mov    rdi,rax
    31b7:	e8 f9 e9 ff ff       	call   1bb5 <threshold_tree_check_complete_structure>
    31bc:	83 f8 f6             	cmp    eax,0xfffffff6
    31bf:	74 1f                	je     31e0 <build_a_tree+0x34e>
    31c1:	48 8d 0d 60 59 00 00 	lea    rcx,[rip+0x5960]        # 8b28 <__PRETTY_FUNCTION__.3422>
    31c8:	ba 71 00 00 00       	mov    edx,0x71
    31cd:	48 8d 35 c8 46 00 00 	lea    rsi,[rip+0x46c8]        # 789c <path_0_1_0_0+0x4>
    31d4:	48 8d 3d d5 46 00 00 	lea    rdi,[rip+0x46d5]        # 78b0 <path_0_1_0_0+0x18>
    31db:	e8 40 e3 ff ff       	call   1520 <__assert_fail@plt>
    31e0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    31e4:	41 b9 02 00 00 00    	mov    r9d,0x2
    31ea:	41 b8 02 00 00 00    	mov    r8d,0x2
    31f0:	b9 0a 00 00 00       	mov    ecx,0xa
    31f5:	ba 01 00 00 00       	mov    edx,0x1
    31fa:	48 8d 35 83 46 00 00 	lea    rsi,[rip+0x4683]        # 7884 <path_0>
    3201:	48 89 c7             	mov    rdi,rax
    3204:	e8 06 ec ff ff       	call   1e0f <threshold_tree_add_node>
    3209:	85 c0                	test   eax,eax
    320b:	74 1f                	je     322c <build_a_tree+0x39a>
    320d:	48 8d 0d 14 59 00 00 	lea    rcx,[rip+0x5914]        # 8b28 <__PRETTY_FUNCTION__.3422>
    3214:	ba 73 00 00 00       	mov    edx,0x73
    3219:	48 8d 35 7c 46 00 00 	lea    rsi,[rip+0x467c]        # 789c <path_0_1_0_0+0x4>
    3220:	48 8d 3d 69 4e 00 00 	lea    rdi,[rip+0x4e69]        # 8090 <path_0_1_0_0+0x7f8>
    3227:	e8 f4 e2 ff ff       	call   1520 <__assert_fail@plt>
    322c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    3230:	41 b9 00 00 00 00    	mov    r9d,0x0
    3236:	41 b8 00 00 00 00    	mov    r8d,0x0
    323c:	b9 64 00 00 00       	mov    ecx,0x64
    3241:	ba 02 00 00 00       	mov    edx,0x2
    3246:	48 8d 35 3b 46 00 00 	lea    rsi,[rip+0x463b]        # 7888 <path_0_0>
    324d:	48 89 c7             	mov    rdi,rax
    3250:	e8 ba eb ff ff       	call   1e0f <threshold_tree_add_node>
    3255:	85 c0                	test   eax,eax
    3257:	74 1f                	je     3278 <build_a_tree+0x3e6>
    3259:	48 8d 0d c8 58 00 00 	lea    rcx,[rip+0x58c8]        # 8b28 <__PRETTY_FUNCTION__.3422>
    3260:	ba 74 00 00 00       	mov    edx,0x74
    3265:	48 8d 35 30 46 00 00 	lea    rsi,[rip+0x4630]        # 789c <path_0_1_0_0+0x4>
    326c:	48 8d 3d 75 4e 00 00 	lea    rdi,[rip+0x4e75]        # 80e8 <path_0_1_0_0+0x850>
    3273:	e8 a8 e2 ff ff       	call   1520 <__assert_fail@plt>
    3278:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    327c:	41 b9 00 00 00 00    	mov    r9d,0x0
    3282:	41 b8 00 00 00 00    	mov    r8d,0x0
    3288:	b9 63 00 00 00       	mov    ecx,0x63
    328d:	ba 03 00 00 00       	mov    edx,0x3
    3292:	48 8d 35 f9 45 00 00 	lea    rsi,[rip+0x45f9]        # 7892 <path_0_1_0>
    3299:	48 89 c7             	mov    rdi,rax
    329c:	e8 6e eb ff ff       	call   1e0f <threshold_tree_add_node>
    32a1:	83 f8 fe             	cmp    eax,0xfffffffe
    32a4:	74 1f                	je     32c5 <build_a_tree+0x433>
    32a6:	48 8d 0d 7b 58 00 00 	lea    rcx,[rip+0x587b]        # 8b28 <__PRETTY_FUNCTION__.3422>
    32ad:	ba 75 00 00 00       	mov    edx,0x75
    32b2:	48 8d 35 e3 45 00 00 	lea    rsi,[rip+0x45e3]        # 789c <path_0_1_0_0+0x4>
    32b9:	48 8d 3d 80 4e 00 00 	lea    rdi,[rip+0x4e80]        # 8140 <path_0_1_0_0+0x8a8>
    32c0:	e8 5b e2 ff ff       	call   1520 <__assert_fail@plt>
    32c5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    32c9:	41 b9 01 00 00 00    	mov    r9d,0x1
    32cf:	41 b8 01 00 00 00    	mov    r8d,0x1
    32d5:	b9 65 00 00 00       	mov    ecx,0x65
    32da:	ba 02 00 00 00       	mov    edx,0x2
    32df:	48 8d 35 a4 45 00 00 	lea    rsi,[rip+0x45a4]        # 788a <path_0_1>
    32e6:	48 89 c7             	mov    rdi,rax
    32e9:	e8 21 eb ff ff       	call   1e0f <threshold_tree_add_node>
    32ee:	85 c0                	test   eax,eax
    32f0:	74 1f                	je     3311 <build_a_tree+0x47f>
    32f2:	48 8d 0d 2f 58 00 00 	lea    rcx,[rip+0x582f]        # 8b28 <__PRETTY_FUNCTION__.3422>
    32f9:	ba 76 00 00 00       	mov    edx,0x76
    32fe:	48 8d 35 97 45 00 00 	lea    rsi,[rip+0x4597]        # 789c <path_0_1_0_0+0x4>
    3305:	48 8d 3d 94 4e 00 00 	lea    rdi,[rip+0x4e94]        # 81a0 <path_0_1_0_0+0x908>
    330c:	e8 0f e2 ff ff       	call   1520 <__assert_fail@plt>
    3311:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    3315:	41 b9 00 00 00 00    	mov    r9d,0x0
    331b:	41 b8 00 00 00 00    	mov    r8d,0x0
    3321:	b9 63 00 00 00       	mov    ecx,0x63
    3326:	ba 02 00 00 00       	mov    edx,0x2
    332b:	48 8d 35 5a 45 00 00 	lea    rsi,[rip+0x455a]        # 788c <path_0_2>
    3332:	48 89 c7             	mov    rdi,rax
    3335:	e8 d5 ea ff ff       	call   1e0f <threshold_tree_add_node>
    333a:	83 f8 fe             	cmp    eax,0xfffffffe
    333d:	74 1f                	je     335e <build_a_tree+0x4cc>
    333f:	48 8d 0d e2 57 00 00 	lea    rcx,[rip+0x57e2]        # 8b28 <__PRETTY_FUNCTION__.3422>
    3346:	ba 77 00 00 00       	mov    edx,0x77
    334b:	48 8d 35 4a 45 00 00 	lea    rsi,[rip+0x454a]        # 789c <path_0_1_0_0+0x4>
    3352:	48 8d 3d 9f 4e 00 00 	lea    rdi,[rip+0x4e9f]        # 81f8 <path_0_1_0_0+0x960>
    3359:	e8 c2 e1 ff ff       	call   1520 <__assert_fail@plt>
    335e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    3362:	48 89 c7             	mov    rdi,rax
    3365:	e8 4b e8 ff ff       	call   1bb5 <threshold_tree_check_complete_structure>
    336a:	83 f8 f6             	cmp    eax,0xfffffff6
    336d:	74 1f                	je     338e <build_a_tree+0x4fc>
    336f:	48 8d 0d b2 57 00 00 	lea    rcx,[rip+0x57b2]        # 8b28 <__PRETTY_FUNCTION__.3422>
    3376:	ba 79 00 00 00       	mov    edx,0x79
    337b:	48 8d 35 1a 45 00 00 	lea    rsi,[rip+0x451a]        # 789c <path_0_1_0_0+0x4>
    3382:	48 8d 3d 27 45 00 00 	lea    rdi,[rip+0x4527]        # 78b0 <path_0_1_0_0+0x18>
    3389:	e8 92 e1 ff ff       	call   1520 <__assert_fail@plt>
    338e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    3392:	41 b9 00 00 00 00    	mov    r9d,0x0
    3398:	41 b8 00 00 00 00    	mov    r8d,0x0
    339e:	b9 f2 03 00 00       	mov    ecx,0x3f2
    33a3:	ba 03 00 00 00       	mov    edx,0x3
    33a8:	48 8d 35 e3 44 00 00 	lea    rsi,[rip+0x44e3]        # 7892 <path_0_1_0>
    33af:	48 89 c7             	mov    rdi,rax
    33b2:	e8 58 ea ff ff       	call   1e0f <threshold_tree_add_node>
    33b7:	85 c0                	test   eax,eax
    33b9:	74 1f                	je     33da <build_a_tree+0x548>
    33bb:	48 8d 0d 66 57 00 00 	lea    rcx,[rip+0x5766]        # 8b28 <__PRETTY_FUNCTION__.3422>
    33c2:	ba 7b 00 00 00       	mov    edx,0x7b
    33c7:	48 8d 35 ce 44 00 00 	lea    rsi,[rip+0x44ce]        # 789c <path_0_1_0_0+0x4>
    33ce:	48 8d 3d 7b 4e 00 00 	lea    rdi,[rip+0x4e7b]        # 8250 <path_0_1_0_0+0x9b8>
    33d5:	e8 46 e1 ff ff       	call   1520 <__assert_fail@plt>
    33da:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    33de:	41 b9 00 00 00 00    	mov    r9d,0x0
    33e4:	41 b8 00 00 00 00    	mov    r8d,0x0
    33ea:	b9 63 00 00 00       	mov    ecx,0x63
    33ef:	ba 03 00 00 00       	mov    edx,0x3
    33f4:	48 8d 35 97 44 00 00 	lea    rsi,[rip+0x4497]        # 7892 <path_0_1_0>
    33fb:	48 89 c7             	mov    rdi,rax
    33fe:	e8 0c ea ff ff       	call   1e0f <threshold_tree_add_node>
    3403:	83 f8 fe             	cmp    eax,0xfffffffe
    3406:	74 1f                	je     3427 <build_a_tree+0x595>
    3408:	48 8d 0d 19 57 00 00 	lea    rcx,[rip+0x5719]        # 8b28 <__PRETTY_FUNCTION__.3422>
    340f:	ba 7c 00 00 00       	mov    edx,0x7c
    3414:	48 8d 35 81 44 00 00 	lea    rsi,[rip+0x4481]        # 789c <path_0_1_0_0+0x4>
    341b:	48 8d 3d 1e 4d 00 00 	lea    rdi,[rip+0x4d1e]        # 8140 <path_0_1_0_0+0x8a8>
    3422:	e8 f9 e0 ff ff       	call   1520 <__assert_fail@plt>
    3427:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    342b:	41 b9 00 00 00 00    	mov    r9d,0x0
    3431:	41 b8 00 00 00 00    	mov    r8d,0x0
    3437:	b9 63 00 00 00       	mov    ecx,0x63
    343c:	ba 03 00 00 00       	mov    edx,0x3
    3441:	48 8d 35 4d 44 00 00 	lea    rsi,[rip+0x444d]        # 7895 <path_0_1_1>
    3448:	48 89 c7             	mov    rdi,rax
    344b:	e8 bf e9 ff ff       	call   1e0f <threshold_tree_add_node>
    3450:	83 f8 fe             	cmp    eax,0xfffffffe
    3453:	74 1f                	je     3474 <build_a_tree+0x5e2>
    3455:	48 8d 0d cc 56 00 00 	lea    rcx,[rip+0x56cc]        # 8b28 <__PRETTY_FUNCTION__.3422>
    345c:	ba 7d 00 00 00       	mov    edx,0x7d
    3461:	48 8d 35 34 44 00 00 	lea    rsi,[rip+0x4434]        # 789c <path_0_1_0_0+0x4>
    3468:	48 8d 3d 39 4e 00 00 	lea    rdi,[rip+0x4e39]        # 82a8 <path_0_1_0_0+0xa10>
    346f:	e8 ac e0 ff ff       	call   1520 <__assert_fail@plt>
    3474:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    3478:	41 b9 00 00 00 00    	mov    r9d,0x0
    347e:	41 b8 00 00 00 00    	mov    r8d,0x0
    3484:	b9 63 00 00 00       	mov    ecx,0x63
    3489:	ba 04 00 00 00       	mov    edx,0x4
    348e:	48 8d 35 03 44 00 00 	lea    rsi,[rip+0x4403]        # 7898 <path_0_1_0_0>
    3495:	48 89 c7             	mov    rdi,rax
    3498:	e8 72 e9 ff ff       	call   1e0f <threshold_tree_add_node>
    349d:	83 f8 fe             	cmp    eax,0xfffffffe
    34a0:	74 1f                	je     34c1 <build_a_tree+0x62f>
    34a2:	48 8d 0d 7f 56 00 00 	lea    rcx,[rip+0x567f]        # 8b28 <__PRETTY_FUNCTION__.3422>
    34a9:	ba 7e 00 00 00       	mov    edx,0x7e
    34ae:	48 8d 35 e7 43 00 00 	lea    rsi,[rip+0x43e7]        # 789c <path_0_1_0_0+0x4>
    34b5:	48 8d 3d 4c 4e 00 00 	lea    rdi,[rip+0x4e4c]        # 8308 <path_0_1_0_0+0xa70>
    34bc:	e8 5f e0 ff ff       	call   1520 <__assert_fail@plt>
    34c1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    34c5:	48 89 c7             	mov    rdi,rax
    34c8:	e8 e8 e6 ff ff       	call   1bb5 <threshold_tree_check_complete_structure>
    34cd:	83 f8 f6             	cmp    eax,0xfffffff6
    34d0:	74 1f                	je     34f1 <build_a_tree+0x65f>
    34d2:	48 8d 0d 4f 56 00 00 	lea    rcx,[rip+0x564f]        # 8b28 <__PRETTY_FUNCTION__.3422>
    34d9:	ba 80 00 00 00       	mov    edx,0x80
    34de:	48 8d 35 b7 43 00 00 	lea    rsi,[rip+0x43b7]        # 789c <path_0_1_0_0+0x4>
    34e5:	48 8d 3d c4 43 00 00 	lea    rdi,[rip+0x43c4]        # 78b0 <path_0_1_0_0+0x18>
    34ec:	e8 2f e0 ff ff       	call   1520 <__assert_fail@plt>
    34f1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    34f5:	41 b9 00 00 00 00    	mov    r9d,0x0
    34fb:	41 b8 00 00 00 00    	mov    r8d,0x0
    3501:	b9 65 00 00 00       	mov    ecx,0x65
    3506:	ba 01 00 00 00       	mov    edx,0x1
    350b:	48 8d 35 74 43 00 00 	lea    rsi,[rip+0x4374]        # 7886 <path_2>
    3512:	48 89 c7             	mov    rdi,rax
    3515:	e8 f5 e8 ff ff       	call   1e0f <threshold_tree_add_node>
    351a:	83 f8 f9             	cmp    eax,0xfffffff9
    351d:	74 1f                	je     353e <build_a_tree+0x6ac>
    351f:	48 8d 0d 02 56 00 00 	lea    rcx,[rip+0x5602]        # 8b28 <__PRETTY_FUNCTION__.3422>
    3526:	ba 82 00 00 00       	mov    edx,0x82
    352b:	48 8d 35 6a 43 00 00 	lea    rsi,[rip+0x436a]        # 789c <path_0_1_0_0+0x4>
    3532:	48 8d 3d 2f 4e 00 00 	lea    rdi,[rip+0x4e2f]        # 8368 <path_0_1_0_0+0xad0>
    3539:	e8 e2 df ff ff       	call   1520 <__assert_fail@plt>
    353e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    3542:	41 b9 00 00 00 00    	mov    r9d,0x0
    3548:	41 b8 00 00 00 00    	mov    r8d,0x0
    354e:	b9 0c 00 00 00       	mov    ecx,0xc
    3553:	ba 01 00 00 00       	mov    edx,0x1
    3558:	48 8d 35 27 43 00 00 	lea    rsi,[rip+0x4327]        # 7886 <path_2>
    355f:	48 89 c7             	mov    rdi,rax
    3562:	e8 a8 e8 ff ff       	call   1e0f <threshold_tree_add_node>
    3567:	85 c0                	test   eax,eax
    3569:	74 1f                	je     358a <build_a_tree+0x6f8>
    356b:	48 8d 0d b6 55 00 00 	lea    rcx,[rip+0x55b6]        # 8b28 <__PRETTY_FUNCTION__.3422>
    3572:	ba 83 00 00 00       	mov    edx,0x83
    3577:	48 8d 35 1e 43 00 00 	lea    rsi,[rip+0x431e]        # 789c <path_0_1_0_0+0x4>
    357e:	48 8d 3d 3b 4e 00 00 	lea    rdi,[rip+0x4e3b]        # 83c0 <path_0_1_0_0+0xb28>
    3585:	e8 96 df ff ff       	call   1520 <__assert_fail@plt>
    358a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    358e:	48 89 c7             	mov    rdi,rax
    3591:	e8 1f e6 ff ff       	call   1bb5 <threshold_tree_check_complete_structure>
    3596:	85 c0                	test   eax,eax
    3598:	74 1f                	je     35b9 <build_a_tree+0x727>
    359a:	48 8d 0d 87 55 00 00 	lea    rcx,[rip+0x5587]        # 8b28 <__PRETTY_FUNCTION__.3422>
    35a1:	ba 85 00 00 00       	mov    edx,0x85
    35a6:	48 8d 35 ef 42 00 00 	lea    rsi,[rip+0x42ef]        # 789c <path_0_1_0_0+0x4>
    35ad:	48 8d 3d 6c 47 00 00 	lea    rdi,[rip+0x476c]        # 7d20 <path_0_1_0_0+0x488>
    35b4:	e8 67 df ff ff       	call   1520 <__assert_fail@plt>
    35b9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    35bd:	41 b9 00 00 00 00    	mov    r9d,0x0
    35c3:	41 b8 00 00 00 00    	mov    r8d,0x0
    35c9:	b9 63 00 00 00       	mov    ecx,0x63
    35ce:	ba 01 00 00 00       	mov    edx,0x1
    35d3:	48 8d 35 ad 42 00 00 	lea    rsi,[rip+0x42ad]        # 7887 <path_3>
    35da:	48 89 c7             	mov    rdi,rax
    35dd:	e8 2d e8 ff ff       	call   1e0f <threshold_tree_add_node>
    35e2:	83 f8 fe             	cmp    eax,0xfffffffe
    35e5:	74 1f                	je     3606 <build_a_tree+0x774>
    35e7:	48 8d 0d 3a 55 00 00 	lea    rcx,[rip+0x553a]        # 8b28 <__PRETTY_FUNCTION__.3422>
    35ee:	ba 87 00 00 00       	mov    edx,0x87
    35f3:	48 8d 35 a2 42 00 00 	lea    rsi,[rip+0x42a2]        # 789c <path_0_1_0_0+0x4>
    35fa:	48 8d 3d 17 4e 00 00 	lea    rdi,[rip+0x4e17]        # 8418 <path_0_1_0_0+0xb80>
    3601:	e8 1a df ff ff       	call   1520 <__assert_fail@plt>
    3606:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    360a:	48 89 c7             	mov    rdi,rax
    360d:	e8 a3 e5 ff ff       	call   1bb5 <threshold_tree_check_complete_structure>
    3612:	85 c0                	test   eax,eax
    3614:	74 1f                	je     3635 <build_a_tree+0x7a3>
    3616:	48 8d 0d 0b 55 00 00 	lea    rcx,[rip+0x550b]        # 8b28 <__PRETTY_FUNCTION__.3422>
    361d:	ba 89 00 00 00       	mov    edx,0x89
    3622:	48 8d 35 73 42 00 00 	lea    rsi,[rip+0x4273]        # 789c <path_0_1_0_0+0x4>
    3629:	48 8d 3d f0 46 00 00 	lea    rdi,[rip+0x46f0]        # 7d20 <path_0_1_0_0+0x488>
    3630:	e8 eb de ff ff       	call   1520 <__assert_fail@plt>
    3635:	90                   	nop
    3636:	c9                   	leave  
    3637:	c3                   	ret    

0000000000003638 <lookup_in_built_tree>:
    3638:	55                   	push   rbp
    3639:	48 89 e5             	mov    rbp,rsp
    363c:	48 83 ec 20          	sub    rsp,0x20
    3640:	48 89 7d e8          	mov    QWORD PTR [rbp-0x18],rdi
    3644:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    364b:	00 00 
    364d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    3651:	31 c0                	xor    eax,eax
    3653:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
    365a:	00 
    365b:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
    365f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    3663:	be 00 00 00 00       	mov    esi,0x0
    3668:	48 89 c7             	mov    rdi,rax
    366b:	e8 1e e7 ff ff       	call   1d8e <threshold_tree_get_node_by_id>
    3670:	83 f8 fa             	cmp    eax,0xfffffffa
    3673:	74 1f                	je     3694 <lookup_in_built_tree+0x5c>
    3675:	48 8d 0d c4 54 00 00 	lea    rcx,[rip+0x54c4]        # 8b40 <__PRETTY_FUNCTION__.3427>
    367c:	ba 90 00 00 00       	mov    edx,0x90
    3681:	48 8d 35 14 42 00 00 	lea    rsi,[rip+0x4214]        # 789c <path_0_1_0_0+0x4>
    3688:	48 8d 3d e1 4d 00 00 	lea    rdi,[rip+0x4de1]        # 8470 <path_0_1_0_0+0xbd8>
    368f:	e8 8c de ff ff       	call   1520 <__assert_fail@plt>
    3694:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    3698:	48 85 c0             	test   rax,rax
    369b:	74 1f                	je     36bc <lookup_in_built_tree+0x84>
    369d:	48 8d 0d 9c 54 00 00 	lea    rcx,[rip+0x549c]        # 8b40 <__PRETTY_FUNCTION__.3427>
    36a4:	ba 91 00 00 00       	mov    edx,0x91
    36a9:	48 8d 35 ec 41 00 00 	lea    rsi,[rip+0x41ec]        # 789c <path_0_1_0_0+0x4>
    36b0:	48 8d 3d 09 43 00 00 	lea    rdi,[rip+0x4309]        # 79c0 <path_0_1_0_0+0x128>
    36b7:	e8 64 de ff ff       	call   1520 <__assert_fail@plt>
    36bc:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
    36c0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    36c4:	be 01 00 00 00       	mov    esi,0x1
    36c9:	48 89 c7             	mov    rdi,rax
    36cc:	e8 bd e6 ff ff       	call   1d8e <threshold_tree_get_node_by_id>
    36d1:	85 c0                	test   eax,eax
    36d3:	74 1f                	je     36f4 <lookup_in_built_tree+0xbc>
    36d5:	48 8d 0d 64 54 00 00 	lea    rcx,[rip+0x5464]        # 8b40 <__PRETTY_FUNCTION__.3427>
    36dc:	ba 93 00 00 00       	mov    edx,0x93
    36e1:	48 8d 35 b4 41 00 00 	lea    rsi,[rip+0x41b4]        # 789c <path_0_1_0_0+0x4>
    36e8:	48 8d 3d d9 4d 00 00 	lea    rdi,[rip+0x4dd9]        # 84c8 <path_0_1_0_0+0xc30>
    36ef:	e8 2c de ff ff       	call   1520 <__assert_fail@plt>
    36f4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    36f8:	48 85 c0             	test   rax,rax
    36fb:	75 1f                	jne    371c <lookup_in_built_tree+0xe4>
    36fd:	48 8d 0d 3c 54 00 00 	lea    rcx,[rip+0x543c]        # 8b40 <__PRETTY_FUNCTION__.3427>
    3704:	ba 94 00 00 00       	mov    edx,0x94
    3709:	48 8d 35 8c 41 00 00 	lea    rsi,[rip+0x418c]        # 789c <path_0_1_0_0+0x4>
    3710:	48 8d 3d 03 4e 00 00 	lea    rdi,[rip+0x4e03]        # 851a <path_0_1_0_0+0xc82>
    3717:	e8 04 de ff ff       	call   1520 <__assert_fail@plt>
    371c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    3720:	0f b6 40 08          	movzx  eax,BYTE PTR [rax+0x8]
    3724:	3c 03                	cmp    al,0x3
    3726:	74 1f                	je     3747 <lookup_in_built_tree+0x10f>
    3728:	48 8d 0d 11 54 00 00 	lea    rcx,[rip+0x5411]        # 8b40 <__PRETTY_FUNCTION__.3427>
    372f:	ba 95 00 00 00       	mov    edx,0x95
    3734:	48 8d 35 61 41 00 00 	lea    rsi,[rip+0x4161]        # 789c <path_0_1_0_0+0x4>
    373b:	48 8d 3d f2 4d 00 00 	lea    rdi,[rip+0x4df2]        # 8534 <path_0_1_0_0+0xc9c>
    3742:	e8 d9 dd ff ff       	call   1520 <__assert_fail@plt>
    3747:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
    374b:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    374f:	be 0c 00 00 00       	mov    esi,0xc
    3754:	48 89 c7             	mov    rdi,rax
    3757:	e8 32 e6 ff ff       	call   1d8e <threshold_tree_get_node_by_id>
    375c:	85 c0                	test   eax,eax
    375e:	74 1f                	je     377f <lookup_in_built_tree+0x147>
    3760:	48 8d 0d d9 53 00 00 	lea    rcx,[rip+0x53d9]        # 8b40 <__PRETTY_FUNCTION__.3427>
    3767:	ba 97 00 00 00       	mov    edx,0x97
    376c:	48 8d 35 29 41 00 00 	lea    rsi,[rip+0x4129]        # 789c <path_0_1_0_0+0x4>
    3773:	48 8d 3d d6 4d 00 00 	lea    rdi,[rip+0x4dd6]        # 8550 <path_0_1_0_0+0xcb8>
    377a:	e8 a1 dd ff ff       	call   1520 <__assert_fail@plt>
    377f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    3783:	48 85 c0             	test   rax,rax
    3786:	75 1f                	jne    37a7 <lookup_in_built_tree+0x16f>
    3788:	48 8d 0d b1 53 00 00 	lea    rcx,[rip+0x53b1]        # 8b40 <__PRETTY_FUNCTION__.3427>
    378f:	ba 98 00 00 00       	mov    edx,0x98
    3794:	48 8d 35 01 41 00 00 	lea    rsi,[rip+0x4101]        # 789c <path_0_1_0_0+0x4>
    379b:	48 8d 3d 78 4d 00 00 	lea    rdi,[rip+0x4d78]        # 851a <path_0_1_0_0+0xc82>
    37a2:	e8 79 dd ff ff       	call   1520 <__assert_fail@plt>
    37a7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    37ab:	0f b6 40 08          	movzx  eax,BYTE PTR [rax+0x8]
    37af:	84 c0                	test   al,al
    37b1:	74 1f                	je     37d2 <lookup_in_built_tree+0x19a>
    37b3:	48 8d 0d 86 53 00 00 	lea    rcx,[rip+0x5386]        # 8b40 <__PRETTY_FUNCTION__.3427>
    37ba:	ba 99 00 00 00       	mov    edx,0x99
    37bf:	48 8d 35 d6 40 00 00 	lea    rsi,[rip+0x40d6]        # 789c <path_0_1_0_0+0x4>
    37c6:	48 8d 3d d6 4d 00 00 	lea    rdi,[rip+0x4dd6]        # 85a3 <path_0_1_0_0+0xd0b>
    37cd:	e8 4e dd ff ff       	call   1520 <__assert_fail@plt>
    37d2:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
    37d6:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    37da:	be 0d 00 00 00       	mov    esi,0xd
    37df:	48 89 c7             	mov    rdi,rax
    37e2:	e8 a7 e5 ff ff       	call   1d8e <threshold_tree_get_node_by_id>
    37e7:	83 f8 fa             	cmp    eax,0xfffffffa
    37ea:	74 1f                	je     380b <lookup_in_built_tree+0x1d3>
    37ec:	48 8d 0d 4d 53 00 00 	lea    rcx,[rip+0x534d]        # 8b40 <__PRETTY_FUNCTION__.3427>
    37f3:	ba 9b 00 00 00       	mov    edx,0x9b
    37f8:	48 8d 35 9d 40 00 00 	lea    rsi,[rip+0x409d]        # 789c <path_0_1_0_0+0x4>
    37ff:	48 8d 3d ba 4d 00 00 	lea    rdi,[rip+0x4dba]        # 85c0 <path_0_1_0_0+0xd28>
    3806:	e8 15 dd ff ff       	call   1520 <__assert_fail@plt>
    380b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    380f:	48 85 c0             	test   rax,rax
    3812:	74 1f                	je     3833 <lookup_in_built_tree+0x1fb>
    3814:	48 8d 0d 25 53 00 00 	lea    rcx,[rip+0x5325]        # 8b40 <__PRETTY_FUNCTION__.3427>
    381b:	ba 9c 00 00 00       	mov    edx,0x9c
    3820:	48 8d 35 75 40 00 00 	lea    rsi,[rip+0x4075]        # 789c <path_0_1_0_0+0x4>
    3827:	48 8d 3d 92 41 00 00 	lea    rdi,[rip+0x4192]        # 79c0 <path_0_1_0_0+0x128>
    382e:	e8 ed dc ff ff       	call   1520 <__assert_fail@plt>
    3833:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
    3837:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    383b:	be 0a 00 00 00       	mov    esi,0xa
    3840:	48 89 c7             	mov    rdi,rax
    3843:	e8 46 e5 ff ff       	call   1d8e <threshold_tree_get_node_by_id>
    3848:	85 c0                	test   eax,eax
    384a:	74 1f                	je     386b <lookup_in_built_tree+0x233>
    384c:	48 8d 0d ed 52 00 00 	lea    rcx,[rip+0x52ed]        # 8b40 <__PRETTY_FUNCTION__.3427>
    3853:	ba 9e 00 00 00       	mov    edx,0x9e
    3858:	48 8d 35 3d 40 00 00 	lea    rsi,[rip+0x403d]        # 789c <path_0_1_0_0+0x4>
    385f:	48 8d 3d b2 4d 00 00 	lea    rdi,[rip+0x4db2]        # 8618 <path_0_1_0_0+0xd80>
    3866:	e8 b5 dc ff ff       	call   1520 <__assert_fail@plt>
    386b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    386f:	48 85 c0             	test   rax,rax
    3872:	75 1f                	jne    3893 <lookup_in_built_tree+0x25b>
    3874:	48 8d 0d c5 52 00 00 	lea    rcx,[rip+0x52c5]        # 8b40 <__PRETTY_FUNCTION__.3427>
    387b:	ba 9f 00 00 00       	mov    edx,0x9f
    3880:	48 8d 35 15 40 00 00 	lea    rsi,[rip+0x4015]        # 789c <path_0_1_0_0+0x4>
    3887:	48 8d 3d 8c 4c 00 00 	lea    rdi,[rip+0x4c8c]        # 851a <path_0_1_0_0+0xc82>
    388e:	e8 8d dc ff ff       	call   1520 <__assert_fail@plt>
    3893:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    3897:	0f b6 40 08          	movzx  eax,BYTE PTR [rax+0x8]
    389b:	3c 02                	cmp    al,0x2
    389d:	74 1f                	je     38be <lookup_in_built_tree+0x286>
    389f:	48 8d 0d 9a 52 00 00 	lea    rcx,[rip+0x529a]        # 8b40 <__PRETTY_FUNCTION__.3427>
    38a6:	ba a0 00 00 00       	mov    edx,0xa0
    38ab:	48 8d 35 ea 3f 00 00 	lea    rsi,[rip+0x3fea]        # 789c <path_0_1_0_0+0x4>
    38b2:	48 8d 3d b2 4d 00 00 	lea    rdi,[rip+0x4db2]        # 866b <path_0_1_0_0+0xdd3>
    38b9:	e8 62 dc ff ff       	call   1520 <__assert_fail@plt>
    38be:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
    38c2:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    38c6:	be 65 00 00 00       	mov    esi,0x65
    38cb:	48 89 c7             	mov    rdi,rax
    38ce:	e8 bb e4 ff ff       	call   1d8e <threshold_tree_get_node_by_id>
    38d3:	85 c0                	test   eax,eax
    38d5:	74 1f                	je     38f6 <lookup_in_built_tree+0x2be>
    38d7:	48 8d 0d 62 52 00 00 	lea    rcx,[rip+0x5262]        # 8b40 <__PRETTY_FUNCTION__.3427>
    38de:	ba a2 00 00 00       	mov    edx,0xa2
    38e3:	48 8d 35 b2 3f 00 00 	lea    rsi,[rip+0x3fb2]        # 789c <path_0_1_0_0+0x4>
    38ea:	48 8d 3d 97 4d 00 00 	lea    rdi,[rip+0x4d97]        # 8688 <path_0_1_0_0+0xdf0>
    38f1:	e8 2a dc ff ff       	call   1520 <__assert_fail@plt>
    38f6:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    38fa:	48 85 c0             	test   rax,rax
    38fd:	75 1f                	jne    391e <lookup_in_built_tree+0x2e6>
    38ff:	48 8d 0d 3a 52 00 00 	lea    rcx,[rip+0x523a]        # 8b40 <__PRETTY_FUNCTION__.3427>
    3906:	ba a3 00 00 00       	mov    edx,0xa3
    390b:	48 8d 35 8a 3f 00 00 	lea    rsi,[rip+0x3f8a]        # 789c <path_0_1_0_0+0x4>
    3912:	48 8d 3d 01 4c 00 00 	lea    rdi,[rip+0x4c01]        # 851a <path_0_1_0_0+0xc82>
    3919:	e8 02 dc ff ff       	call   1520 <__assert_fail@plt>
    391e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    3922:	0f b6 40 08          	movzx  eax,BYTE PTR [rax+0x8]
    3926:	3c 01                	cmp    al,0x1
    3928:	74 1f                	je     3949 <lookup_in_built_tree+0x311>
    392a:	48 8d 0d 0f 52 00 00 	lea    rcx,[rip+0x520f]        # 8b40 <__PRETTY_FUNCTION__.3427>
    3931:	ba a4 00 00 00       	mov    edx,0xa4
    3936:	48 8d 35 5f 3f 00 00 	lea    rsi,[rip+0x3f5f]        # 789c <path_0_1_0_0+0x4>
    393d:	48 8d 3d 98 4d 00 00 	lea    rdi,[rip+0x4d98]        # 86dc <path_0_1_0_0+0xe44>
    3944:	e8 d7 db ff ff       	call   1520 <__assert_fail@plt>
    3949:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
    394d:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    3951:	be f3 03 00 00       	mov    esi,0x3f3
    3956:	48 89 c7             	mov    rdi,rax
    3959:	e8 30 e4 ff ff       	call   1d8e <threshold_tree_get_node_by_id>
    395e:	83 f8 fa             	cmp    eax,0xfffffffa
    3961:	74 1f                	je     3982 <lookup_in_built_tree+0x34a>
    3963:	48 8d 0d d6 51 00 00 	lea    rcx,[rip+0x51d6]        # 8b40 <__PRETTY_FUNCTION__.3427>
    396a:	ba a6 00 00 00       	mov    edx,0xa6
    396f:	48 8d 35 26 3f 00 00 	lea    rsi,[rip+0x3f26]        # 789c <path_0_1_0_0+0x4>
    3976:	48 8d 3d 7b 4d 00 00 	lea    rdi,[rip+0x4d7b]        # 86f8 <path_0_1_0_0+0xe60>
    397d:	e8 9e db ff ff       	call   1520 <__assert_fail@plt>
    3982:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    3986:	48 85 c0             	test   rax,rax
    3989:	74 1f                	je     39aa <lookup_in_built_tree+0x372>
    398b:	48 8d 0d ae 51 00 00 	lea    rcx,[rip+0x51ae]        # 8b40 <__PRETTY_FUNCTION__.3427>
    3992:	ba a7 00 00 00       	mov    edx,0xa7
    3997:	48 8d 35 fe 3e 00 00 	lea    rsi,[rip+0x3efe]        # 789c <path_0_1_0_0+0x4>
    399e:	48 8d 3d 1b 40 00 00 	lea    rdi,[rip+0x401b]        # 79c0 <path_0_1_0_0+0x128>
    39a5:	e8 76 db ff ff       	call   1520 <__assert_fail@plt>
    39aa:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
    39ae:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    39b2:	48 89 d1             	mov    rcx,rdx
    39b5:	ba 00 00 00 00       	mov    edx,0x0
    39ba:	48 8d 35 c3 3e 00 00 	lea    rsi,[rip+0x3ec3]        # 7884 <path_0>
    39c1:	48 89 c7             	mov    rdi,rax
    39c4:	e8 a8 e2 ff ff       	call   1c71 <threshold_tree_get_node_by_path>
    39c9:	85 c0                	test   eax,eax
    39cb:	74 1f                	je     39ec <lookup_in_built_tree+0x3b4>
    39cd:	48 8d 0d 6c 51 00 00 	lea    rcx,[rip+0x516c]        # 8b40 <__PRETTY_FUNCTION__.3427>
    39d4:	ba a9 00 00 00       	mov    edx,0xa9
    39d9:	48 8d 35 bc 3e 00 00 	lea    rsi,[rip+0x3ebc]        # 789c <path_0_1_0_0+0x4>
    39e0:	48 8d 3d 69 4d 00 00 	lea    rdi,[rip+0x4d69]        # 8750 <path_0_1_0_0+0xeb8>
    39e7:	e8 34 db ff ff       	call   1520 <__assert_fail@plt>
    39ec:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    39f0:	48 85 c0             	test   rax,rax
    39f3:	75 1f                	jne    3a14 <lookup_in_built_tree+0x3dc>
    39f5:	48 8d 0d 44 51 00 00 	lea    rcx,[rip+0x5144]        # 8b40 <__PRETTY_FUNCTION__.3427>
    39fc:	ba aa 00 00 00       	mov    edx,0xaa
    3a01:	48 8d 35 94 3e 00 00 	lea    rsi,[rip+0x3e94]        # 789c <path_0_1_0_0+0x4>
    3a08:	48 8d 3d 0b 4b 00 00 	lea    rdi,[rip+0x4b0b]        # 851a <path_0_1_0_0+0xc82>
    3a0f:	e8 0c db ff ff       	call   1520 <__assert_fail@plt>
    3a14:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    3a18:	48 8b 00             	mov    rax,QWORD PTR [rax]
    3a1b:	48 83 f8 01          	cmp    rax,0x1
    3a1f:	74 1f                	je     3a40 <lookup_in_built_tree+0x408>
    3a21:	48 8d 0d 18 51 00 00 	lea    rcx,[rip+0x5118]        # 8b40 <__PRETTY_FUNCTION__.3427>
    3a28:	ba ab 00 00 00       	mov    edx,0xab
    3a2d:	48 8d 35 68 3e 00 00 	lea    rsi,[rip+0x3e68]        # 789c <path_0_1_0_0+0x4>
    3a34:	48 8d 3d 71 4d 00 00 	lea    rdi,[rip+0x4d71]        # 87ac <path_0_1_0_0+0xf14>
    3a3b:	e8 e0 da ff ff       	call   1520 <__assert_fail@plt>
    3a40:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
    3a44:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    3a48:	48 89 d1             	mov    rcx,rdx
    3a4b:	ba 01 00 00 00       	mov    edx,0x1
    3a50:	48 8d 35 2d 3e 00 00 	lea    rsi,[rip+0x3e2d]        # 7884 <path_0>
    3a57:	48 89 c7             	mov    rdi,rax
    3a5a:	e8 12 e2 ff ff       	call   1c71 <threshold_tree_get_node_by_path>
    3a5f:	85 c0                	test   eax,eax
    3a61:	74 1f                	je     3a82 <lookup_in_built_tree+0x44a>
    3a63:	48 8d 0d d6 50 00 00 	lea    rcx,[rip+0x50d6]        # 8b40 <__PRETTY_FUNCTION__.3427>
    3a6a:	ba ad 00 00 00       	mov    edx,0xad
    3a6f:	48 8d 35 26 3e 00 00 	lea    rsi,[rip+0x3e26]        # 789c <path_0_1_0_0+0x4>
    3a76:	48 8d 3d 43 4d 00 00 	lea    rdi,[rip+0x4d43]        # 87c0 <path_0_1_0_0+0xf28>
    3a7d:	e8 9e da ff ff       	call   1520 <__assert_fail@plt>
    3a82:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    3a86:	48 85 c0             	test   rax,rax
    3a89:	75 1f                	jne    3aaa <lookup_in_built_tree+0x472>
    3a8b:	48 8d 0d ae 50 00 00 	lea    rcx,[rip+0x50ae]        # 8b40 <__PRETTY_FUNCTION__.3427>
    3a92:	ba ae 00 00 00       	mov    edx,0xae
    3a97:	48 8d 35 fe 3d 00 00 	lea    rsi,[rip+0x3dfe]        # 789c <path_0_1_0_0+0x4>
    3a9e:	48 8d 3d 75 4a 00 00 	lea    rdi,[rip+0x4a75]        # 851a <path_0_1_0_0+0xc82>
    3aa5:	e8 76 da ff ff       	call   1520 <__assert_fail@plt>
    3aaa:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    3aae:	48 8b 00             	mov    rax,QWORD PTR [rax]
    3ab1:	48 83 f8 0a          	cmp    rax,0xa
    3ab5:	74 1f                	je     3ad6 <lookup_in_built_tree+0x49e>
    3ab7:	48 8d 0d 82 50 00 00 	lea    rcx,[rip+0x5082]        # 8b40 <__PRETTY_FUNCTION__.3427>
    3abe:	ba af 00 00 00       	mov    edx,0xaf
    3ac3:	48 8d 35 d2 3d 00 00 	lea    rsi,[rip+0x3dd2]        # 789c <path_0_1_0_0+0x4>
    3aca:	48 8d 3d 4b 4d 00 00 	lea    rdi,[rip+0x4d4b]        # 881c <path_0_1_0_0+0xf84>
    3ad1:	e8 4a da ff ff       	call   1520 <__assert_fail@plt>
    3ad6:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
    3ada:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    3ade:	48 89 d1             	mov    rcx,rdx
    3ae1:	ba 01 00 00 00       	mov    edx,0x1
    3ae6:	48 8d 35 98 3d 00 00 	lea    rsi,[rip+0x3d98]        # 7885 <path_1>
    3aed:	48 89 c7             	mov    rdi,rax
    3af0:	e8 7c e1 ff ff       	call   1c71 <threshold_tree_get_node_by_path>
    3af5:	85 c0                	test   eax,eax
    3af7:	74 1f                	je     3b18 <lookup_in_built_tree+0x4e0>
    3af9:	48 8d 0d 40 50 00 00 	lea    rcx,[rip+0x5040]        # 8b40 <__PRETTY_FUNCTION__.3427>
    3b00:	ba b1 00 00 00       	mov    edx,0xb1
    3b05:	48 8d 35 90 3d 00 00 	lea    rsi,[rip+0x3d90]        # 789c <path_0_1_0_0+0x4>
    3b0c:	48 8d 3d 25 4d 00 00 	lea    rdi,[rip+0x4d25]        # 8838 <path_0_1_0_0+0xfa0>
    3b13:	e8 08 da ff ff       	call   1520 <__assert_fail@plt>
    3b18:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    3b1c:	48 85 c0             	test   rax,rax
    3b1f:	75 1f                	jne    3b40 <lookup_in_built_tree+0x508>
    3b21:	48 8d 0d 18 50 00 00 	lea    rcx,[rip+0x5018]        # 8b40 <__PRETTY_FUNCTION__.3427>
    3b28:	ba b2 00 00 00       	mov    edx,0xb2
    3b2d:	48 8d 35 68 3d 00 00 	lea    rsi,[rip+0x3d68]        # 789c <path_0_1_0_0+0x4>
    3b34:	48 8d 3d df 49 00 00 	lea    rdi,[rip+0x49df]        # 851a <path_0_1_0_0+0xc82>
    3b3b:	e8 e0 d9 ff ff       	call   1520 <__assert_fail@plt>
    3b40:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    3b44:	48 8b 00             	mov    rax,QWORD PTR [rax]
    3b47:	48 83 f8 0b          	cmp    rax,0xb
    3b4b:	74 1f                	je     3b6c <lookup_in_built_tree+0x534>
    3b4d:	48 8d 0d ec 4f 00 00 	lea    rcx,[rip+0x4fec]        # 8b40 <__PRETTY_FUNCTION__.3427>
    3b54:	ba b3 00 00 00       	mov    edx,0xb3
    3b59:	48 8d 35 3c 3d 00 00 	lea    rsi,[rip+0x3d3c]        # 789c <path_0_1_0_0+0x4>
    3b60:	48 8d 3d 2d 4d 00 00 	lea    rdi,[rip+0x4d2d]        # 8894 <path_0_1_0_0+0xffc>
    3b67:	e8 b4 d9 ff ff       	call   1520 <__assert_fail@plt>
    3b6c:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
    3b70:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    3b74:	48 89 d1             	mov    rcx,rdx
    3b77:	ba 03 00 00 00       	mov    edx,0x3
    3b7c:	48 8d 35 0f 3d 00 00 	lea    rsi,[rip+0x3d0f]        # 7892 <path_0_1_0>
    3b83:	48 89 c7             	mov    rdi,rax
    3b86:	e8 e6 e0 ff ff       	call   1c71 <threshold_tree_get_node_by_path>
    3b8b:	85 c0                	test   eax,eax
    3b8d:	74 1f                	je     3bae <lookup_in_built_tree+0x576>
    3b8f:	48 8d 0d aa 4f 00 00 	lea    rcx,[rip+0x4faa]        # 8b40 <__PRETTY_FUNCTION__.3427>
    3b96:	ba b5 00 00 00       	mov    edx,0xb5
    3b9b:	48 8d 35 fa 3c 00 00 	lea    rsi,[rip+0x3cfa]        # 789c <path_0_1_0_0+0x4>
    3ba2:	48 8d 3d 07 4d 00 00 	lea    rdi,[rip+0x4d07]        # 88b0 <path_0_1_0_0+0x1018>
    3ba9:	e8 72 d9 ff ff       	call   1520 <__assert_fail@plt>
    3bae:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    3bb2:	48 85 c0             	test   rax,rax
    3bb5:	75 1f                	jne    3bd6 <lookup_in_built_tree+0x59e>
    3bb7:	48 8d 0d 82 4f 00 00 	lea    rcx,[rip+0x4f82]        # 8b40 <__PRETTY_FUNCTION__.3427>
    3bbe:	ba b6 00 00 00       	mov    edx,0xb6
    3bc3:	48 8d 35 d2 3c 00 00 	lea    rsi,[rip+0x3cd2]        # 789c <path_0_1_0_0+0x4>
    3bca:	48 8d 3d 49 49 00 00 	lea    rdi,[rip+0x4949]        # 851a <path_0_1_0_0+0xc82>
    3bd1:	e8 4a d9 ff ff       	call   1520 <__assert_fail@plt>
    3bd6:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    3bda:	48 8b 00             	mov    rax,QWORD PTR [rax]
    3bdd:	48 3d f2 03 00 00    	cmp    rax,0x3f2
    3be3:	74 1f                	je     3c04 <lookup_in_built_tree+0x5cc>
    3be5:	48 8d 0d 54 4f 00 00 	lea    rcx,[rip+0x4f54]        # 8b40 <__PRETTY_FUNCTION__.3427>
    3bec:	ba b7 00 00 00       	mov    edx,0xb7
    3bf1:	48 8d 35 a4 3c 00 00 	lea    rsi,[rip+0x3ca4]        # 789c <path_0_1_0_0+0x4>
    3bf8:	48 8d 3d 11 4d 00 00 	lea    rdi,[rip+0x4d11]        # 8910 <path_0_1_0_0+0x1078>
    3bff:	e8 1c d9 ff ff       	call   1520 <__assert_fail@plt>
    3c04:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
    3c08:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    3c0c:	48 89 d1             	mov    rcx,rdx
    3c0f:	ba 04 00 00 00       	mov    edx,0x4
    3c14:	48 8d 35 7d 3c 00 00 	lea    rsi,[rip+0x3c7d]        # 7898 <path_0_1_0_0>
    3c1b:	48 89 c7             	mov    rdi,rax
    3c1e:	e8 4e e0 ff ff       	call   1c71 <threshold_tree_get_node_by_path>
    3c23:	83 f8 fe             	cmp    eax,0xfffffffe
    3c26:	74 1f                	je     3c47 <lookup_in_built_tree+0x60f>
    3c28:	48 8d 0d 11 4f 00 00 	lea    rcx,[rip+0x4f11]        # 8b40 <__PRETTY_FUNCTION__.3427>
    3c2f:	ba b9 00 00 00       	mov    edx,0xb9
    3c34:	48 8d 35 61 3c 00 00 	lea    rsi,[rip+0x3c61]        # 789c <path_0_1_0_0+0x4>
    3c3b:	48 8d 3d e6 4c 00 00 	lea    rdi,[rip+0x4ce6]        # 8928 <path_0_1_0_0+0x1090>
    3c42:	e8 d9 d8 ff ff       	call   1520 <__assert_fail@plt>
    3c47:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    3c4b:	48 85 c0             	test   rax,rax
    3c4e:	74 1f                	je     3c6f <lookup_in_built_tree+0x637>
    3c50:	48 8d 0d e9 4e 00 00 	lea    rcx,[rip+0x4ee9]        # 8b40 <__PRETTY_FUNCTION__.3427>
    3c57:	ba ba 00 00 00       	mov    edx,0xba
    3c5c:	48 8d 35 39 3c 00 00 	lea    rsi,[rip+0x3c39]        # 789c <path_0_1_0_0+0x4>
    3c63:	48 8d 3d 56 3d 00 00 	lea    rdi,[rip+0x3d56]        # 79c0 <path_0_1_0_0+0x128>
    3c6a:	e8 b1 d8 ff ff       	call   1520 <__assert_fail@plt>
    3c6f:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
    3c73:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    3c77:	48 89 d1             	mov    rcx,rdx
    3c7a:	ba 03 00 00 00       	mov    edx,0x3
    3c7f:	48 8d 35 0f 3c 00 00 	lea    rsi,[rip+0x3c0f]        # 7895 <path_0_1_1>
    3c86:	48 89 c7             	mov    rdi,rax
    3c89:	e8 e3 df ff ff       	call   1c71 <threshold_tree_get_node_by_path>
    3c8e:	83 f8 fe             	cmp    eax,0xfffffffe
    3c91:	74 1f                	je     3cb2 <lookup_in_built_tree+0x67a>
    3c93:	48 8d 0d a6 4e 00 00 	lea    rcx,[rip+0x4ea6]        # 8b40 <__PRETTY_FUNCTION__.3427>
    3c9a:	ba bc 00 00 00       	mov    edx,0xbc
    3c9f:	48 8d 35 f6 3b 00 00 	lea    rsi,[rip+0x3bf6]        # 789c <path_0_1_0_0+0x4>
    3ca6:	48 8d 3d e3 4c 00 00 	lea    rdi,[rip+0x4ce3]        # 8990 <path_0_1_0_0+0x10f8>
    3cad:	e8 6e d8 ff ff       	call   1520 <__assert_fail@plt>
    3cb2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    3cb6:	48 85 c0             	test   rax,rax
    3cb9:	74 1f                	je     3cda <lookup_in_built_tree+0x6a2>
    3cbb:	48 8d 0d 7e 4e 00 00 	lea    rcx,[rip+0x4e7e]        # 8b40 <__PRETTY_FUNCTION__.3427>
    3cc2:	ba bd 00 00 00       	mov    edx,0xbd
    3cc7:	48 8d 35 ce 3b 00 00 	lea    rsi,[rip+0x3bce]        # 789c <path_0_1_0_0+0x4>
    3cce:	48 8d 3d eb 3c 00 00 	lea    rdi,[rip+0x3ceb]        # 79c0 <path_0_1_0_0+0x128>
    3cd5:	e8 46 d8 ff ff       	call   1520 <__assert_fail@plt>
    3cda:	90                   	nop
    3cdb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    3cdf:	64 48 33 04 25 28 00 	xor    rax,QWORD PTR fs:0x28
    3ce6:	00 00 
    3ce8:	74 05                	je     3cef <lookup_in_built_tree+0x6b7>
    3cea:	e8 01 da ff ff       	call   16f0 <__stack_chk_fail@plt>
    3cef:	c9                   	leave  
    3cf0:	c3                   	ret    

0000000000003cf1 <share_secret>:
    3cf1:	55                   	push   rbp
    3cf2:	48 89 e5             	mov    rbp,rsp
    3cf5:	48 83 ec 10          	sub    rsp,0x10
    3cf9:	48 89 7d f8          	mov    QWORD PTR [rbp-0x8],rdi
    3cfd:	48 89 75 f0          	mov    QWORD PTR [rbp-0x10],rsi
    3d01:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
    3d05:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    3d09:	48 89 d6             	mov    rsi,rdx
    3d0c:	48 89 c7             	mov    rdi,rax
    3d0f:	e8 8a e6 ff ff       	call   239e <threshold_tree_share_secret>
    3d14:	85 c0                	test   eax,eax
    3d16:	74 1f                	je     3d37 <share_secret+0x46>
    3d18:	48 8d 0d 39 4e 00 00 	lea    rcx,[rip+0x4e39]        # 8b58 <__PRETTY_FUNCTION__.3432>
    3d1f:	ba c1 00 00 00       	mov    edx,0xc1
    3d24:	48 8d 35 71 3b 00 00 	lea    rsi,[rip+0x3b71]        # 789c <path_0_1_0_0+0x4>
    3d2b:	48 8d 3d c6 4c 00 00 	lea    rdi,[rip+0x4cc6]        # 89f8 <path_0_1_0_0+0x1160>
    3d32:	e8 e9 d7 ff ff       	call   1520 <__assert_fail@plt>
    3d37:	90                   	nop
    3d38:	c9                   	leave  
    3d39:	c3                   	ret    

0000000000003d3a <main>:
    3d3a:	55                   	push   rbp
    3d3b:	48 89 e5             	mov    rbp,rsp
    3d3e:	48 83 ec 70          	sub    rsp,0x70
    3d42:	89 7d 9c             	mov    DWORD PTR [rbp-0x64],edi
    3d45:	48 89 75 90          	mov    QWORD PTR [rbp-0x70],rsi
    3d49:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    3d50:	00 00 
    3d52:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    3d56:	31 c0                	xor    eax,eax
    3d58:	48 b8 30 31 32 33 34 	movabs rax,0x3736353433323130
    3d5f:	35 36 37 
    3d62:	48 ba 38 39 30 31 32 	movabs rdx,0x3534333231303938
    3d69:	33 34 35 
    3d6c:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
    3d70:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
    3d74:	48 b8 36 37 38 39 30 	movabs rax,0x3332313039383736
    3d7b:	31 32 33 
    3d7e:	48 ba 34 35 36 37 38 	movabs rdx,0x3231393837363534
    3d85:	39 31 32 
    3d88:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
    3d8c:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
    3d90:	c6 45 f0 00          	mov    BYTE PTR [rbp-0x10],0x0
    3d94:	48 c7 45 c0 00 00 00 	mov    QWORD PTR [rbp-0x40],0x0
    3d9b:	00 
    3d9c:	ba 00 00 00 00       	mov    edx,0x0
    3da1:	be 38 15 00 00       	mov    esi,0x1538
    3da6:	bf 00 00 00 00       	mov    edi,0x0
    3dab:	e8 de df ff ff       	call   1d8e <threshold_tree_get_node_by_id>
    3db0:	83 f8 f8             	cmp    eax,0xfffffff8
    3db3:	74 1f                	je     3dd4 <main+0x9a>
    3db5:	48 8d 0d a9 4d 00 00 	lea    rcx,[rip+0x4da9]        # 8b65 <__PRETTY_FUNCTION__.3439>
    3dbc:	ba ca 00 00 00       	mov    edx,0xca
    3dc1:	48 8d 35 d4 3a 00 00 	lea    rsi,[rip+0x3ad4]        # 789c <path_0_1_0_0+0x4>
    3dc8:	48 8d 3d 71 4c 00 00 	lea    rdi,[rip+0x4c71]        # 8a40 <path_0_1_0_0+0x11a8>
    3dcf:	e8 4c d7 ff ff       	call   1520 <__assert_fail@plt>
    3dd4:	b8 00 00 00 00       	mov    eax,0x0
    3dd9:	e8 e7 db ff ff       	call   19c5 <threshold_tree_ctx_new>
    3dde:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
    3de2:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
    3de6:	48 8d 15 af 4c 00 00 	lea    rdx,[rip+0x4caf]        # 8a9c <path_0_1_0_0+0x1204>
    3ded:	48 8d 35 b6 4c 00 00 	lea    rsi,[rip+0x4cb6]        # 8aaa <path_0_1_0_0+0x1212>
    3df4:	48 89 c7             	mov    rdi,rax
    3df7:	e8 63 ec ff ff       	call   2a5f <print_threshold_tree>
    3dfc:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
    3e00:	48 89 c7             	mov    rdi,rax
    3e03:	e8 8a f0 ff ff       	call   2e92 <build_a_tree>
    3e08:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
    3e0c:	48 8d 15 66 3a 00 00 	lea    rdx,[rip+0x3a66]        # 7879 <PRINT_NULL_POINTER+0x41>
    3e13:	48 8d 35 9c 4c 00 00 	lea    rsi,[rip+0x4c9c]        # 8ab6 <path_0_1_0_0+0x121e>
    3e1a:	48 89 c7             	mov    rdi,rax
    3e1d:	e8 3d ec ff ff       	call   2a5f <print_threshold_tree>
    3e22:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
    3e26:	48 89 c7             	mov    rdi,rax
    3e29:	e8 0a f8 ff ff       	call   3638 <lookup_in_built_tree>
    3e2e:	48 8d 55 d0          	lea    rdx,[rbp-0x30]
    3e32:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
    3e36:	48 89 d6             	mov    rsi,rdx
    3e39:	48 89 c7             	mov    rdi,rax
    3e3c:	e8 b0 fe ff ff       	call   3cf1 <share_secret>
    3e41:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
    3e45:	48 8d 15 2d 3a 00 00 	lea    rdx,[rip+0x3a2d]        # 7879 <PRINT_NULL_POINTER+0x41>
    3e4c:	48 8d 35 75 4c 00 00 	lea    rsi,[rip+0x4c75]        # 8ac8 <path_0_1_0_0+0x1230>
    3e53:	48 89 c7             	mov    rdi,rax
    3e56:	e8 04 ec ff ff       	call   2a5f <print_threshold_tree>
    3e5b:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
    3e5f:	48 89 c7             	mov    rdi,rax
    3e62:	e8 af dc ff ff       	call   1b16 <threshold_tree_ctx_free>
    3e67:	b8 00 00 00 00       	mov    eax,0x0
    3e6c:	e8 54 db ff ff       	call   19c5 <threshold_tree_ctx_new>
    3e71:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
    3e75:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
    3e79:	48 83 c0 08          	add    rax,0x8
    3e7d:	48 8b 00             	mov    rax,QWORD PTR [rax]
    3e80:	48 89 c7             	mov    rdi,rax
    3e83:	e8 28 d8 ff ff       	call   16b0 <atoi@plt>
    3e88:	83 c0 03             	add    eax,0x3
    3e8b:	0f b6 d0             	movzx  edx,al
    3e8e:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    3e92:	41 b9 03 00 00 00    	mov    r9d,0x3
    3e98:	41 89 d0             	mov    r8d,edx
    3e9b:	b9 01 00 00 00       	mov    ecx,0x1
    3ea0:	ba 00 00 00 00       	mov    edx,0x0
    3ea5:	48 8d 35 d8 39 00 00 	lea    rsi,[rip+0x39d8]        # 7884 <path_0>
    3eac:	48 89 c7             	mov    rdi,rax
    3eaf:	e8 5b df ff ff       	call   1e0f <threshold_tree_add_node>
    3eb4:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    3eb8:	41 b9 00 00 00 00    	mov    r9d,0x0
    3ebe:	41 b8 00 00 00 00    	mov    r8d,0x0
    3ec4:	b9 0a 00 00 00       	mov    ecx,0xa
    3ec9:	ba 01 00 00 00       	mov    edx,0x1
    3ece:	48 8d 35 af 39 00 00 	lea    rsi,[rip+0x39af]        # 7884 <path_0>
    3ed5:	48 89 c7             	mov    rdi,rax
    3ed8:	e8 32 df ff ff       	call   1e0f <threshold_tree_add_node>
    3edd:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    3ee1:	41 b9 00 00 00 00    	mov    r9d,0x0
    3ee7:	41 b8 00 00 00 00    	mov    r8d,0x0
    3eed:	b9 0b 00 00 00       	mov    ecx,0xb
    3ef2:	ba 01 00 00 00       	mov    edx,0x1
    3ef7:	48 8d 35 87 39 00 00 	lea    rsi,[rip+0x3987]        # 7885 <path_1>
    3efe:	48 89 c7             	mov    rdi,rax
    3f01:	e8 09 df ff ff       	call   1e0f <threshold_tree_add_node>
    3f06:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    3f0a:	41 b9 00 00 00 00    	mov    r9d,0x0
    3f10:	41 b8 00 00 00 00    	mov    r8d,0x0
    3f16:	b9 0c 00 00 00       	mov    ecx,0xc
    3f1b:	ba 01 00 00 00       	mov    edx,0x1
    3f20:	48 8d 35 5f 39 00 00 	lea    rsi,[rip+0x395f]        # 7886 <path_2>
    3f27:	48 89 c7             	mov    rdi,rax
    3f2a:	e8 e0 de ff ff       	call   1e0f <threshold_tree_add_node>
    3f2f:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    3f33:	41 b9 00 00 00 00    	mov    r9d,0x0
    3f39:	41 b8 00 00 00 00    	mov    r8d,0x0
    3f3f:	b9 0d 00 00 00       	mov    ecx,0xd
    3f44:	ba 01 00 00 00       	mov    edx,0x1
    3f49:	48 8d 35 37 39 00 00 	lea    rsi,[rip+0x3937]        # 7887 <path_3>
    3f50:	48 89 c7             	mov    rdi,rax
    3f53:	e8 b7 de ff ff       	call   1e0f <threshold_tree_add_node>
    3f58:	48 8d 55 d0          	lea    rdx,[rbp-0x30]
    3f5c:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    3f60:	48 89 d6             	mov    rsi,rdx
    3f63:	48 89 c7             	mov    rdi,rax
    3f66:	e8 86 fd ff ff       	call   3cf1 <share_secret>
    3f6b:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    3f6f:	48 8d 15 03 39 00 00 	lea    rdx,[rip+0x3903]        # 7879 <PRINT_NULL_POINTER+0x41>
    3f76:	48 8d 35 6b 4b 00 00 	lea    rsi,[rip+0x4b6b]        # 8ae8 <path_0_1_0_0+0x1250>
    3f7d:	48 89 c7             	mov    rdi,rax
    3f80:	e8 da ea ff ff       	call   2a5f <print_threshold_tree>
    3f85:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    3f89:	48 89 c7             	mov    rdi,rax
    3f8c:	e8 c2 e8 ff ff       	call   2853 <test_threshold_tree_verify_all_shares>
    3f91:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    3f95:	48 89 c7             	mov    rdi,rax
    3f98:	e8 79 db ff ff       	call   1b16 <threshold_tree_ctx_free>
    3f9d:	48 c7 45 a8 00 00 00 	mov    QWORD PTR [rbp-0x58],0x0
    3fa4:	00 
    3fa5:	c6 45 a7 02          	mov    BYTE PTR [rbp-0x59],0x2
    3fa9:	0f b6 45 a7          	movzx  eax,BYTE PTR [rbp-0x59]
    3fad:	48 8d 4d b0          	lea    rcx,[rbp-0x50]
    3fb1:	48 8d 55 a8          	lea    rdx,[rbp-0x58]
    3fb5:	89 c6                	mov    esi,eax
    3fb7:	bf 03 00 00 00       	mov    edi,0x3
    3fbc:	e8 7e e5 ff ff       	call   253f <get_all_combinations>
    3fc1:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
    3fc8:	00 
    3fc9:	eb 55                	jmp    4020 <main+0x2e6>
    3fcb:	c6 45 a6 00          	mov    BYTE PTR [rbp-0x5a],0x0
    3fcf:	eb 37                	jmp    4008 <main+0x2ce>
    3fd1:	48 8b 55 a8          	mov    rdx,QWORD PTR [rbp-0x58]
    3fd5:	0f b6 45 a7          	movzx  eax,BYTE PTR [rbp-0x59]
    3fd9:	48 0f af 45 b8       	imul   rax,QWORD PTR [rbp-0x48]
    3fde:	48 89 c1             	mov    rcx,rax
    3fe1:	0f b6 45 a6          	movzx  eax,BYTE PTR [rbp-0x5a]
    3fe5:	48 01 c8             	add    rax,rcx
    3fe8:	48 01 d0             	add    rax,rdx
    3feb:	0f b6 00             	movzx  eax,BYTE PTR [rax]
    3fee:	0f b6 c0             	movzx  eax,al
    3ff1:	89 c6                	mov    esi,eax
    3ff3:	48 8d 3d 0d 4b 00 00 	lea    rdi,[rip+0x4b0d]        # 8b07 <path_0_1_0_0+0x126f>
    3ffa:	b8 00 00 00 00       	mov    eax,0x0
    3fff:	e8 5c d4 ff ff       	call   1460 <printf@plt>
    4004:	80 45 a6 01          	add    BYTE PTR [rbp-0x5a],0x1
    4008:	0f b6 45 a6          	movzx  eax,BYTE PTR [rbp-0x5a]
    400c:	3a 45 a7             	cmp    al,BYTE PTR [rbp-0x59]
    400f:	72 c0                	jb     3fd1 <main+0x297>
    4011:	bf 0a 00 00 00       	mov    edi,0xa
    4016:	e8 35 d5 ff ff       	call   1550 <putchar@plt>
    401b:	48 83 45 b8 01       	add    QWORD PTR [rbp-0x48],0x1
    4020:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
    4024:	48 39 45 b8          	cmp    QWORD PTR [rbp-0x48],rax
    4028:	72 a1                	jb     3fcb <main+0x291>
    402a:	48 8b 45 a8          	mov    rax,QWORD PTR [rbp-0x58]
    402e:	48 89 c7             	mov    rdi,rax
    4031:	e8 ea d5 ff ff       	call   1620 <free@plt>
    4036:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
    403a:	48 89 c6             	mov    rsi,rax
    403d:	48 8d 3d c7 4a 00 00 	lea    rdi,[rip+0x4ac7]        # 8b0b <path_0_1_0_0+0x1273>
    4044:	b8 00 00 00 00       	mov    eax,0x0
    4049:	e8 12 d4 ff ff       	call   1460 <printf@plt>
    404e:	b8 00 00 00 00       	mov    eax,0x0
    4053:	48 8b 4d f8          	mov    rcx,QWORD PTR [rbp-0x8]
    4057:	64 48 33 0c 25 28 00 	xor    rcx,QWORD PTR fs:0x28
    405e:	00 00 
    4060:	74 05                	je     4067 <main+0x32d>
    4062:	e8 89 d6 ff ff       	call   16f0 <__stack_chk_fail@plt>
    4067:	c9                   	leave  
    4068:	c3                   	ret    

0000000000004069 <from_commitments_status>:
    4069:	55                   	push   rbp
    406a:	48 89 e5             	mov    rbp,rsp
    406d:	89 7d fc             	mov    DWORD PTR [rbp-0x4],edi
    4070:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
    4073:	83 f8 fe             	cmp    eax,0xfffffffe
    4076:	74 23                	je     409b <from_commitments_status+0x32>
    4078:	83 f8 fe             	cmp    eax,0xfffffffe
    407b:	7f 07                	jg     4084 <from_commitments_status+0x1b>
    407d:	83 f8 fd             	cmp    eax,0xfffffffd
    4080:	74 20                	je     40a2 <from_commitments_status+0x39>
    4082:	eb 25                	jmp    40a9 <from_commitments_status+0x40>
    4084:	83 f8 ff             	cmp    eax,0xffffffff
    4087:	74 0b                	je     4094 <from_commitments_status+0x2b>
    4089:	85 c0                	test   eax,eax
    408b:	75 1c                	jne    40a9 <from_commitments_status+0x40>
    408d:	b8 00 00 00 00       	mov    eax,0x0
    4092:	eb 1a                	jmp    40ae <from_commitments_status+0x45>
    4094:	b8 ff ff ff ff       	mov    eax,0xffffffff
    4099:	eb 13                	jmp    40ae <from_commitments_status+0x45>
    409b:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    40a0:	eb 0c                	jmp    40ae <from_commitments_status+0x45>
    40a2:	b8 fb ff ff ff       	mov    eax,0xfffffffb
    40a7:	eb 05                	jmp    40ae <from_commitments_status+0x45>
    40a9:	b8 ff ff ff ff       	mov    eax,0xffffffff
    40ae:	5d                   	pop    rbp
    40af:	c3                   	ret    

00000000000040b0 <create_shares>:
    40b0:	55                   	push   rbp
    40b1:	48 89 e5             	mov    rbp,rsp
    40b4:	53                   	push   rbx
    40b5:	48 81 ec 98 00 00 00 	sub    rsp,0x98
    40bc:	48 89 7d 88          	mov    QWORD PTR [rbp-0x78],rdi
    40c0:	89 d0                	mov    eax,edx
    40c2:	48 89 8d 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rcx
    40c9:	4c 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],r8
    40d0:	4c 89 8d 68 ff ff ff 	mov    QWORD PTR [rbp-0x98],r9
    40d7:	89 f2                	mov    edx,esi
    40d9:	88 55 84             	mov    BYTE PTR [rbp-0x7c],dl
    40dc:	88 45 80             	mov    BYTE PTR [rbp-0x80],al
    40df:	c7 45 9c f8 ff ff ff 	mov    DWORD PTR [rbp-0x64],0xfffffff8
    40e6:	48 c7 45 d8 00 00 00 	mov    QWORD PTR [rbp-0x28],0x0
    40ed:	00 
    40ee:	48 c7 45 b0 00 00 00 	mov    QWORD PTR [rbp-0x50],0x0
    40f5:	00 
    40f6:	c7 45 a0 00 00 00 00 	mov    DWORD PTR [rbp-0x60],0x0
    40fd:	48 c7 45 e0 00 00 00 	mov    QWORD PTR [rbp-0x20],0x0
    4104:	00 
    4105:	0f b6 45 84          	movzx  eax,BYTE PTR [rbp-0x7c]
    4109:	be 08 00 00 00       	mov    esi,0x8
    410e:	48 89 c7             	mov    rdi,rax
    4111:	e8 0a d6 ff ff       	call   1720 <calloc@plt>
    4116:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
    411a:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
    411f:	0f 84 7e 04 00 00    	je     45a3 <create_shares+0x4f3>
    4125:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    4129:	48 8b 55 88          	mov    rdx,QWORD PTR [rbp-0x78]
    412d:	48 89 10             	mov    QWORD PTR [rax],rdx
    4130:	48 8b 85 68 ff ff ff 	mov    rax,QWORD PTR [rbp-0x98]
    4137:	48 89 c7             	mov    rdi,rax
    413a:	e8 c1 d6 ff ff       	call   1800 <BN_CTX_start@plt>
    413f:	48 c7 45 b8 01 00 00 	mov    QWORD PTR [rbp-0x48],0x1
    4146:	00 
    4147:	e9 96 00 00 00       	jmp    41e2 <create_shares+0x132>
    414c:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
    4150:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
    4157:	00 
    4158:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    415c:	48 8d 1c 02          	lea    rbx,[rdx+rax*1]
    4160:	48 8b 85 68 ff ff ff 	mov    rax,QWORD PTR [rbp-0x98]
    4167:	48 89 c7             	mov    rdi,rax
    416a:	e8 01 d6 ff ff       	call   1770 <BN_CTX_get@plt>
    416f:	48 89 03             	mov    QWORD PTR [rbx],rax
    4172:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
    4176:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
    417d:	00 
    417e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    4182:	48 01 d0             	add    rax,rdx
    4185:	48 8b 00             	mov    rax,QWORD PTR [rax]
    4188:	48 85 c0             	test   rax,rax
    418b:	0f 84 15 04 00 00    	je     45a6 <create_shares+0x4f6>
    4191:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
    4195:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
    419c:	00 
    419d:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    41a1:	48 01 d0             	add    rax,rdx
    41a4:	48 8b 00             	mov    rax,QWORD PTR [rax]
    41a7:	48 8b 75 10          	mov    rsi,QWORD PTR [rbp+0x10]
    41ab:	48 89 c7             	mov    rdi,rax
    41ae:	e8 4d d4 ff ff       	call   1600 <BN_rand_range@plt>
    41b3:	85 c0                	test   eax,eax
    41b5:	0f 84 ee 03 00 00    	je     45a9 <create_shares+0x4f9>
    41bb:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
    41bf:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
    41c6:	00 
    41c7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    41cb:	48 01 d0             	add    rax,rdx
    41ce:	48 8b 00             	mov    rax,QWORD PTR [rax]
    41d1:	48 89 c7             	mov    rdi,rax
    41d4:	e8 17 d3 ff ff       	call   14f0 <BN_is_zero@plt>
    41d9:	85 c0                	test   eax,eax
    41db:	75 b4                	jne    4191 <create_shares+0xe1>
    41dd:	48 83 45 b8 01       	add    QWORD PTR [rbp-0x48],0x1
    41e2:	0f b6 45 84          	movzx  eax,BYTE PTR [rbp-0x7c]
    41e6:	48 39 45 b8          	cmp    QWORD PTR [rbp-0x48],rax
    41ea:	0f 82 5c ff ff ff    	jb     414c <create_shares+0x9c>
    41f0:	b8 00 00 00 00       	mov    eax,0x0
    41f5:	e8 45 19 00 00       	call   5b3f <secp256k1_algebra_ctx_new>
    41fa:	48 89 c2             	mov    rdx,rax
    41fd:	48 8b 85 70 ff ff ff 	mov    rax,QWORD PTR [rbp-0x90]
    4204:	48 89 10             	mov    QWORD PTR [rax],rdx
    4207:	48 8b 85 70 ff ff ff 	mov    rax,QWORD PTR [rbp-0x90]
    420e:	48 8b 00             	mov    rax,QWORD PTR [rax]
    4211:	48 85 c0             	test   rax,rax
    4214:	0f 84 92 03 00 00    	je     45ac <create_shares+0x4fc>
    421a:	48 8b 85 70 ff ff ff 	mov    rax,QWORD PTR [rbp-0x90]
    4221:	0f b6 55 80          	movzx  edx,BYTE PTR [rbp-0x80]
    4225:	88 50 28             	mov    BYTE PTR [rax+0x28],dl
    4228:	48 8b 85 70 ff ff ff 	mov    rax,QWORD PTR [rbp-0x90]
    422f:	0f b6 55 84          	movzx  edx,BYTE PTR [rbp-0x7c]
    4233:	88 50 29             	mov    BYTE PTR [rax+0x29],dl
    4236:	0f b6 45 80          	movzx  eax,BYTE PTR [rbp-0x80]
    423a:	be 20 00 00 00       	mov    esi,0x20
    423f:	48 89 c7             	mov    rdi,rax
    4242:	e8 d9 d4 ff ff       	call   1720 <calloc@plt>
    4247:	48 89 c2             	mov    rdx,rax
    424a:	48 8b 85 70 ff ff ff 	mov    rax,QWORD PTR [rbp-0x90]
    4251:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
    4255:	48 8b 85 70 ff ff ff 	mov    rax,QWORD PTR [rbp-0x90]
    425c:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
    4260:	48 85 c0             	test   rax,rax
    4263:	0f 84 46 03 00 00    	je     45af <create_shares+0x4ff>
    4269:	0f b6 45 80          	movzx  eax,BYTE PTR [rbp-0x80]
    426d:	be 21 00 00 00       	mov    esi,0x21
    4272:	48 89 c7             	mov    rdi,rax
    4275:	e8 a6 d4 ff ff       	call   1720 <calloc@plt>
    427a:	48 89 c2             	mov    rdx,rax
    427d:	48 8b 85 70 ff ff ff 	mov    rax,QWORD PTR [rbp-0x90]
    4284:	48 89 50 18          	mov    QWORD PTR [rax+0x18],rdx
    4288:	48 8b 85 70 ff ff ff 	mov    rax,QWORD PTR [rbp-0x90]
    428f:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
    4293:	48 85 c0             	test   rax,rax
    4296:	0f 84 16 03 00 00    	je     45b2 <create_shares+0x502>
    429c:	0f b6 45 84          	movzx  eax,BYTE PTR [rbp-0x7c]
    42a0:	be 21 00 00 00       	mov    esi,0x21
    42a5:	48 89 c7             	mov    rdi,rax
    42a8:	e8 73 d4 ff ff       	call   1720 <calloc@plt>
    42ad:	48 89 c2             	mov    rdx,rax
    42b0:	48 8b 85 70 ff ff ff 	mov    rax,QWORD PTR [rbp-0x90]
    42b7:	48 89 50 20          	mov    QWORD PTR [rax+0x20],rdx
    42bb:	48 8b 85 70 ff ff ff 	mov    rax,QWORD PTR [rbp-0x90]
    42c2:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
    42c6:	48 85 c0             	test   rax,rax
    42c9:	0f 84 e6 02 00 00    	je     45b5 <create_shares+0x505>
    42cf:	48 c7 45 c0 00 00 00 	mov    QWORD PTR [rbp-0x40],0x0
    42d6:	00 
    42d7:	e9 e8 00 00 00       	jmp    43c4 <create_shares+0x314>
    42dc:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
    42e0:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
    42e7:	00 
    42e8:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    42ec:	48 01 d0             	add    rax,rdx
    42ef:	48 8b 00             	mov    rax,QWORD PTR [rax]
    42f2:	48 89 c7             	mov    rdi,rax
    42f5:	e8 c6 d2 ff ff       	call   15c0 <BN_num_bits@plt>
    42fa:	83 c0 07             	add    eax,0x7
    42fd:	8d 50 07             	lea    edx,[rax+0x7]
    4300:	85 c0                	test   eax,eax
    4302:	0f 48 c2             	cmovs  eax,edx
    4305:	c1 f8 03             	sar    eax,0x3
    4308:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
    430b:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
    430e:	3b 45 a0             	cmp    eax,DWORD PTR [rbp-0x60]
    4311:	76 1c                	jbe    432f <create_shares+0x27f>
    4313:	8b 55 a8             	mov    edx,DWORD PTR [rbp-0x58]
    4316:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
    431a:	48 89 d6             	mov    rsi,rdx
    431d:	48 89 c7             	mov    rdi,rax
    4320:	e8 9b d4 ff ff       	call   17c0 <realloc@plt>
    4325:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
    4329:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
    432c:	89 45 a0             	mov    DWORD PTR [rbp-0x60],eax
    432f:	48 83 7d b0 00       	cmp    QWORD PTR [rbp-0x50],0x0
    4334:	0f 84 7e 02 00 00    	je     45b8 <create_shares+0x508>
    433a:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
    433e:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
    4345:	00 
    4346:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    434a:	48 01 d0             	add    rax,rdx
    434d:	48 8b 00             	mov    rax,QWORD PTR [rax]
    4350:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
    4354:	48 89 d6             	mov    rsi,rdx
    4357:	48 89 c7             	mov    rdi,rax
    435a:	e8 21 d4 ff ff       	call   1780 <BN_bn2bin@plt>
    435f:	85 c0                	test   eax,eax
    4361:	0f 8e 54 02 00 00    	jle    45bb <create_shares+0x50b>
    4367:	48 8b 85 70 ff ff ff 	mov    rax,QWORD PTR [rbp-0x90]
    436e:	48 8b 48 20          	mov    rcx,QWORD PTR [rax+0x20]
    4372:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
    4376:	48 89 d0             	mov    rax,rdx
    4379:	48 c1 e0 05          	shl    rax,0x5
    437d:	48 01 d0             	add    rax,rdx
    4380:	48 01 c1             	add    rcx,rax
    4383:	48 8b 85 70 ff ff ff 	mov    rax,QWORD PTR [rbp-0x90]
    438a:	48 8b 00             	mov    rax,QWORD PTR [rax]
    438d:	8b 55 a8             	mov    edx,DWORD PTR [rbp-0x58]
    4390:	48 8b 75 b0          	mov    rsi,QWORD PTR [rbp-0x50]
    4394:	48 89 c7             	mov    rdi,rax
    4397:	e8 81 18 00 00       	call   5c1d <secp256k1_algebra_generate_proof_for_data>
    439c:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
    439f:	83 7d ac 00          	cmp    DWORD PTR [rbp-0x54],0x0
    43a3:	74 1a                	je     43bf <create_shares+0x30f>
    43a5:	83 7d ac fc          	cmp    DWORD PTR [rbp-0x54],0xfffffffc
    43a9:	75 07                	jne    43b2 <create_shares+0x302>
    43ab:	b8 f8 ff ff ff       	mov    eax,0xfffffff8
    43b0:	eb 05                	jmp    43b7 <create_shares+0x307>
    43b2:	b8 ff ff ff ff       	mov    eax,0xffffffff
    43b7:	89 45 9c             	mov    DWORD PTR [rbp-0x64],eax
    43ba:	e9 0f 02 00 00       	jmp    45ce <create_shares+0x51e>
    43bf:	48 83 45 c0 01       	add    QWORD PTR [rbp-0x40],0x1
    43c4:	0f b6 45 84          	movzx  eax,BYTE PTR [rbp-0x7c]
    43c8:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
    43cc:	0f 82 0a ff ff ff    	jb     42dc <create_shares+0x22c>
    43d2:	8b 55 a0             	mov    edx,DWORD PTR [rbp-0x60]
    43d5:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
    43d9:	be 00 00 00 00       	mov    esi,0x0
    43de:	48 89 c7             	mov    rdi,rax
    43e1:	e8 aa d0 ff ff       	call   1490 <memset@plt>
    43e6:	48 8b 85 68 ff ff ff 	mov    rax,QWORD PTR [rbp-0x98]
    43ed:	48 89 c7             	mov    rdi,rax
    43f0:	e8 7b d3 ff ff       	call   1770 <BN_CTX_get@plt>
    43f5:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
    43f9:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
    43fe:	0f 84 ba 01 00 00    	je     45be <create_shares+0x50e>
    4404:	48 8b 85 68 ff ff ff 	mov    rax,QWORD PTR [rbp-0x98]
    440b:	48 89 c7             	mov    rdi,rax
    440e:	e8 5d d3 ff ff       	call   1770 <BN_CTX_get@plt>
    4413:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
    4417:	48 83 7d e0 00       	cmp    QWORD PTR [rbp-0x20],0x0
    441c:	0f 84 9f 01 00 00    	je     45c1 <create_shares+0x511>
    4422:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
    4429:	00 
    442a:	e9 5d 01 00 00       	jmp    458c <create_shares+0x4dc>
    442f:	48 83 7d e0 00       	cmp    QWORD PTR [rbp-0x20],0x0
    4434:	0f 84 8a 01 00 00    	je     45c4 <create_shares+0x514>
    443a:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
    443e:	48 89 c7             	mov    rdi,rax
    4441:	e8 5a d2 ff ff       	call   16a0 <BN_zero_ex@plt>
    4446:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
    444d:	00 
    444e:	e9 85 00 00 00       	jmp    44d8 <create_shares+0x428>
    4453:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
    4457:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
    445e:	00 
    445f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    4463:	48 01 d0             	add    rax,rdx
    4466:	48 8b 10             	mov    rdx,QWORD PTR [rax]
    4469:	0f b6 45 84          	movzx  eax,BYTE PTR [rbp-0x7c]
    446d:	48 0f af 45 c8       	imul   rax,QWORD PTR [rbp-0x38]
    4472:	48 89 c1             	mov    rcx,rax
    4475:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
    4479:	48 01 c8             	add    rax,rcx
    447c:	48 8d 0c c5 00 00 00 	lea    rcx,[rax*8+0x0]
    4483:	00 
    4484:	48 8b 85 78 ff ff ff 	mov    rax,QWORD PTR [rbp-0x88]
    448b:	48 01 c8             	add    rax,rcx
    448e:	48 8b 30             	mov    rsi,QWORD PTR [rax]
    4491:	48 8b 8d 68 ff ff ff 	mov    rcx,QWORD PTR [rbp-0x98]
    4498:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    449c:	49 89 c8             	mov    r8,rcx
    449f:	48 8b 4d 10          	mov    rcx,QWORD PTR [rbp+0x10]
    44a3:	48 89 c7             	mov    rdi,rax
    44a6:	e8 15 d0 ff ff       	call   14c0 <BN_mod_mul@plt>
    44ab:	85 c0                	test   eax,eax
    44ad:	0f 84 14 01 00 00    	je     45c7 <create_shares+0x517>
    44b3:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
    44b7:	48 8b 75 e0          	mov    rsi,QWORD PTR [rbp-0x20]
    44bb:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
    44bf:	48 8b 4d 10          	mov    rcx,QWORD PTR [rbp+0x10]
    44c3:	48 89 c7             	mov    rdi,rax
    44c6:	e8 65 d2 ff ff       	call   1730 <BN_mod_add_quick@plt>
    44cb:	85 c0                	test   eax,eax
    44cd:	0f 84 f7 00 00 00    	je     45ca <create_shares+0x51a>
    44d3:	48 83 45 d0 01       	add    QWORD PTR [rbp-0x30],0x1
    44d8:	0f b6 45 84          	movzx  eax,BYTE PTR [rbp-0x7c]
    44dc:	48 39 45 d0          	cmp    QWORD PTR [rbp-0x30],rax
    44e0:	0f 82 6d ff ff ff    	jb     4453 <create_shares+0x3a3>
    44e6:	48 8b 85 70 ff ff ff 	mov    rax,QWORD PTR [rbp-0x90]
    44ed:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
    44f1:	48 8b 55 c8          	mov    rdx,QWORD PTR [rbp-0x38]
    44f5:	48 c1 e2 05          	shl    rdx,0x5
    44f9:	48 8d 0c 10          	lea    rcx,[rax+rdx*1]
    44fd:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
    4501:	ba 20 00 00 00       	mov    edx,0x20
    4506:	48 89 ce             	mov    rsi,rcx
    4509:	48 89 c7             	mov    rdi,rax
    450c:	e8 9f cf ff ff       	call   14b0 <BN_bn2binpad@plt>
    4511:	85 c0                	test   eax,eax
    4513:	0f 8e b4 00 00 00    	jle    45cd <create_shares+0x51d>
    4519:	48 8b 85 70 ff ff ff 	mov    rax,QWORD PTR [rbp-0x90]
    4520:	48 8b 48 18          	mov    rcx,QWORD PTR [rax+0x18]
    4524:	48 8b 55 c8          	mov    rdx,QWORD PTR [rbp-0x38]
    4528:	48 89 d0             	mov    rax,rdx
    452b:	48 c1 e0 05          	shl    rax,0x5
    452f:	48 01 d0             	add    rax,rdx
    4532:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
    4536:	48 8b 85 70 ff ff ff 	mov    rax,QWORD PTR [rbp-0x90]
    453d:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
    4541:	48 8b 4d c8          	mov    rcx,QWORD PTR [rbp-0x38]
    4545:	48 c1 e1 05          	shl    rcx,0x5
    4549:	48 8d 34 08          	lea    rsi,[rax+rcx*1]
    454d:	48 8b 85 70 ff ff ff 	mov    rax,QWORD PTR [rbp-0x90]
    4554:	48 8b 00             	mov    rax,QWORD PTR [rax]
    4557:	48 89 d1             	mov    rcx,rdx
    455a:	ba 20 00 00 00       	mov    edx,0x20
    455f:	48 89 c7             	mov    rdi,rax
    4562:	e8 b6 16 00 00       	call   5c1d <secp256k1_algebra_generate_proof_for_data>
    4567:	89 45 a4             	mov    DWORD PTR [rbp-0x5c],eax
    456a:	83 7d a4 00          	cmp    DWORD PTR [rbp-0x5c],0x0
    456e:	74 17                	je     4587 <create_shares+0x4d7>
    4570:	83 7d a4 fc          	cmp    DWORD PTR [rbp-0x5c],0xfffffffc
    4574:	75 07                	jne    457d <create_shares+0x4cd>
    4576:	b8 f8 ff ff ff       	mov    eax,0xfffffff8
    457b:	eb 05                	jmp    4582 <create_shares+0x4d2>
    457d:	b8 ff ff ff ff       	mov    eax,0xffffffff
    4582:	89 45 9c             	mov    DWORD PTR [rbp-0x64],eax
    4585:	eb 47                	jmp    45ce <create_shares+0x51e>
    4587:	48 83 45 c8 01       	add    QWORD PTR [rbp-0x38],0x1
    458c:	0f b6 45 80          	movzx  eax,BYTE PTR [rbp-0x80]
    4590:	48 39 45 c8          	cmp    QWORD PTR [rbp-0x38],rax
    4594:	0f 82 95 fe ff ff    	jb     442f <create_shares+0x37f>
    459a:	c7 45 9c 00 00 00 00 	mov    DWORD PTR [rbp-0x64],0x0
    45a1:	eb 2b                	jmp    45ce <create_shares+0x51e>
    45a3:	90                   	nop
    45a4:	eb 28                	jmp    45ce <create_shares+0x51e>
    45a6:	90                   	nop
    45a7:	eb 25                	jmp    45ce <create_shares+0x51e>
    45a9:	90                   	nop
    45aa:	eb 22                	jmp    45ce <create_shares+0x51e>
    45ac:	90                   	nop
    45ad:	eb 1f                	jmp    45ce <create_shares+0x51e>
    45af:	90                   	nop
    45b0:	eb 1c                	jmp    45ce <create_shares+0x51e>
    45b2:	90                   	nop
    45b3:	eb 19                	jmp    45ce <create_shares+0x51e>
    45b5:	90                   	nop
    45b6:	eb 16                	jmp    45ce <create_shares+0x51e>
    45b8:	90                   	nop
    45b9:	eb 13                	jmp    45ce <create_shares+0x51e>
    45bb:	90                   	nop
    45bc:	eb 10                	jmp    45ce <create_shares+0x51e>
    45be:	90                   	nop
    45bf:	eb 0d                	jmp    45ce <create_shares+0x51e>
    45c1:	90                   	nop
    45c2:	eb 0a                	jmp    45ce <create_shares+0x51e>
    45c4:	90                   	nop
    45c5:	eb 07                	jmp    45ce <create_shares+0x51e>
    45c7:	90                   	nop
    45c8:	eb 04                	jmp    45ce <create_shares+0x51e>
    45ca:	90                   	nop
    45cb:	eb 01                	jmp    45ce <create_shares+0x51e>
    45cd:	90                   	nop
    45ce:	48 8b 85 68 ff ff ff 	mov    rax,QWORD PTR [rbp-0x98]
    45d5:	48 89 c7             	mov    rdi,rax
    45d8:	e8 f3 d1 ff ff       	call   17d0 <BN_CTX_end@plt>
    45dd:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    45e1:	48 89 c7             	mov    rdi,rax
    45e4:	e8 37 d0 ff ff       	call   1620 <free@plt>
    45e9:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
    45ed:	48 89 c7             	mov    rdi,rax
    45f0:	e8 2b d0 ff ff       	call   1620 <free@plt>
    45f5:	8b 45 9c             	mov    eax,DWORD PTR [rbp-0x64]
    45f8:	48 81 c4 98 00 00 00 	add    rsp,0x98
    45ff:	5b                   	pop    rbx
    4600:	5d                   	pop    rbp
    4601:	c3                   	ret    

0000000000004602 <verifiable_secret_sharing_split_impl>:
    4602:	55                   	push   rbp
    4603:	48 89 e5             	mov    rbp,rsp
    4606:	48 83 ec 60          	sub    rsp,0x60
    460a:	48 89 7d c8          	mov    QWORD PTR [rbp-0x38],rdi
    460e:	89 75 c4             	mov    DWORD PTR [rbp-0x3c],esi
    4611:	89 c8                	mov    eax,ecx
    4613:	4c 89 45 b0          	mov    QWORD PTR [rbp-0x50],r8
    4617:	4c 89 4d a8          	mov    QWORD PTR [rbp-0x58],r9
    461b:	88 55 c0             	mov    BYTE PTR [rbp-0x40],dl
    461e:	88 45 bc             	mov    BYTE PTR [rbp-0x44],al
    4621:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
    4628:	00 
    4629:	48 c7 45 e0 00 00 00 	mov    QWORD PTR [rbp-0x20],0x0
    4630:	00 
    4631:	c7 45 dc f8 ff ff ff 	mov    DWORD PTR [rbp-0x24],0xfffffff8
    4638:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
    463f:	00 
    4640:	be 30 00 00 00       	mov    esi,0x30
    4645:	bf 01 00 00 00       	mov    edi,0x1
    464a:	e8 d1 d0 ff ff       	call   1720 <calloc@plt>
    464f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    4653:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    4658:	75 0a                	jne    4664 <verifiable_secret_sharing_split_impl+0x62>
    465a:	b8 f8 ff ff ff       	mov    eax,0xfffffff8
    465f:	e9 d0 01 00 00       	jmp    4834 <verifiable_secret_sharing_split_impl+0x232>
    4664:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
    4667:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    466b:	ba 00 00 00 00       	mov    edx,0x0
    4670:	89 ce                	mov    esi,ecx
    4672:	48 89 c7             	mov    rdi,rax
    4675:	e8 06 cf ff ff       	call   1580 <BN_bin2bn@plt>
    467a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
    467e:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
    4683:	0f 84 5d 01 00 00    	je     47e6 <verifiable_secret_sharing_split_impl+0x1e4>
    4689:	ba 00 00 00 00       	mov    edx,0x0
    468e:	be 20 00 00 00       	mov    esi,0x20
    4693:	48 8d 3d 86 45 00 00 	lea    rdi,[rip+0x4586]        # 8c20 <SECP256K1_FIELD>
    469a:	e8 e1 ce ff ff       	call   1580 <BN_bin2bn@plt>
    469f:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
    46a3:	48 83 7d e0 00       	cmp    QWORD PTR [rbp-0x20],0x0
    46a8:	0f 84 3b 01 00 00    	je     47e9 <verifiable_secret_sharing_split_impl+0x1e7>
    46ae:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
    46b2:	48 89 c7             	mov    rdi,rax
    46b5:	e8 46 d1 ff ff       	call   1800 <BN_CTX_start@plt>
    46ba:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
    46be:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
    46c2:	b9 00 00 00 00       	mov    ecx,0x0
    46c7:	be e8 03 00 00       	mov    esi,0x3e8
    46cc:	48 89 c7             	mov    rdi,rax
    46cf:	e8 ac cf ff ff       	call   1680 <BN_is_prime_ex@plt>
    46d4:	85 c0                	test   eax,eax
    46d6:	75 1f                	jne    46f7 <verifiable_secret_sharing_split_impl+0xf5>
    46d8:	48 8d 0d 01 45 00 00 	lea    rcx,[rip+0x4501]        # 8be0 <__PRETTY_FUNCTION__.5407>
    46df:	ba 9e 00 00 00       	mov    edx,0x9e
    46e4:	48 8d 35 95 44 00 00 	lea    rsi,[rip+0x4495]        # 8b80 <__PRETTY_FUNCTION__.3439+0x1b>
    46eb:	48 8d 3d ae 44 00 00 	lea    rdi,[rip+0x44ae]        # 8ba0 <__PRETTY_FUNCTION__.3439+0x3b>
    46f2:	e8 29 ce ff ff       	call   1520 <__assert_fail@plt>
    46f7:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
    46fb:	be 04 00 00 00       	mov    esi,0x4
    4700:	48 89 c7             	mov    rdi,rax
    4703:	e8 78 cd ff ff       	call   1480 <BN_set_flags@plt>
    4708:	48 8b 55 e0          	mov    rdx,QWORD PTR [rbp-0x20]
    470c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    4710:	48 89 d6             	mov    rsi,rdx
    4713:	48 89 c7             	mov    rdi,rax
    4716:	e8 f5 ce ff ff       	call   1610 <BN_cmp@plt>
    471b:	85 c0                	test   eax,eax
    471d:	78 0c                	js     472b <verifiable_secret_sharing_split_impl+0x129>
    471f:	c7 45 dc fc ff ff ff 	mov    DWORD PTR [rbp-0x24],0xfffffffc
    4726:	e9 c2 00 00 00       	jmp    47ed <verifiable_secret_sharing_split_impl+0x1eb>
    472b:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
    4732:	00 
    4733:	eb 49                	jmp    477e <verifiable_secret_sharing_split_impl+0x17c>
    4735:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    4739:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
    4740:	00 
    4741:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
    4745:	48 01 d0             	add    rax,rdx
    4748:	48 8b 10             	mov    rdx,QWORD PTR [rax]
    474b:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    474f:	48 8d 0c c5 00 00 00 	lea    rcx,[rax*8+0x0]
    4756:	00 
    4757:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
    475b:	48 01 c8             	add    rax,rcx
    475e:	48 8b 00             	mov    rax,QWORD PTR [rax]
    4761:	48 8b 75 18          	mov    rsi,QWORD PTR [rbp+0x18]
    4765:	48 8b 4d e0          	mov    rcx,QWORD PTR [rbp-0x20]
    4769:	49 89 f0             	mov    r8,rsi
    476c:	48 89 c6             	mov    rsi,rax
    476f:	bf 00 00 00 00       	mov    edi,0x0
    4774:	e8 d7 cc ff ff       	call   1450 <BN_div@plt>
    4779:	48 83 45 e8 01       	add    QWORD PTR [rbp-0x18],0x1
    477e:	0f b6 55 c0          	movzx  edx,BYTE PTR [rbp-0x40]
    4782:	0f b6 45 bc          	movzx  eax,BYTE PTR [rbp-0x44]
    4786:	0f af c2             	imul   eax,edx
    4789:	48 98                	cdqe   
    478b:	48 39 45 e8          	cmp    QWORD PTR [rbp-0x18],rax
    478f:	72 a4                	jb     4735 <verifiable_secret_sharing_split_impl+0x133>
    4791:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    4795:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
    4799:	48 89 50 08          	mov    QWORD PTR [rax+0x8],rdx
    479d:	0f b6 55 bc          	movzx  edx,BYTE PTR [rbp-0x44]
    47a1:	0f b6 75 c0          	movzx  esi,BYTE PTR [rbp-0x40]
    47a5:	4c 8b 45 18          	mov    r8,QWORD PTR [rbp+0x18]
    47a9:	48 8b 7d f8          	mov    rdi,QWORD PTR [rbp-0x8]
    47ad:	48 8b 4d b0          	mov    rcx,QWORD PTR [rbp-0x50]
    47b1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    47b5:	48 83 ec 08          	sub    rsp,0x8
    47b9:	ff 75 e0             	push   QWORD PTR [rbp-0x20]
    47bc:	4d 89 c1             	mov    r9,r8
    47bf:	49 89 f8             	mov    r8,rdi
    47c2:	48 89 c7             	mov    rdi,rax
    47c5:	e8 e6 f8 ff ff       	call   40b0 <create_shares>
    47ca:	48 83 c4 10          	add    rsp,0x10
    47ce:	85 c0                	test   eax,eax
    47d0:	75 1a                	jne    47ec <verifiable_secret_sharing_split_impl+0x1ea>
    47d2:	48 8b 45 a8          	mov    rax,QWORD PTR [rbp-0x58]
    47d6:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
    47da:	48 89 10             	mov    QWORD PTR [rax],rdx
    47dd:	c7 45 dc 00 00 00 00 	mov    DWORD PTR [rbp-0x24],0x0
    47e4:	eb 07                	jmp    47ed <verifiable_secret_sharing_split_impl+0x1eb>
    47e6:	90                   	nop
    47e7:	eb 04                	jmp    47ed <verifiable_secret_sharing_split_impl+0x1eb>
    47e9:	90                   	nop
    47ea:	eb 01                	jmp    47ed <verifiable_secret_sharing_split_impl+0x1eb>
    47ec:	90                   	nop
    47ed:	48 83 7d e0 00       	cmp    QWORD PTR [rbp-0x20],0x0
    47f2:	74 0c                	je     4800 <verifiable_secret_sharing_split_impl+0x1fe>
    47f4:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
    47f8:	48 89 c7             	mov    rdi,rax
    47fb:	e8 20 d0 ff ff       	call   1820 <BN_free@plt>
    4800:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
    4805:	74 0c                	je     4813 <verifiable_secret_sharing_split_impl+0x211>
    4807:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    480b:	48 89 c7             	mov    rdi,rax
    480e:	e8 2d ce ff ff       	call   1640 <BN_clear_free@plt>
    4813:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
    4817:	48 89 c7             	mov    rdi,rax
    481a:	e8 b1 cf ff ff       	call   17d0 <BN_CTX_end@plt>
    481f:	83 7d dc 00          	cmp    DWORD PTR [rbp-0x24],0x0
    4823:	74 0c                	je     4831 <verifiable_secret_sharing_split_impl+0x22f>
    4825:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    4829:	48 89 c7             	mov    rdi,rax
    482c:	e8 72 12 00 00       	call   5aa3 <verifiable_secret_sharing_free_shares>
    4831:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
    4834:	c9                   	leave  
    4835:	c3                   	ret    

0000000000004836 <verifiable_secret_sharing_split>:
    4836:	55                   	push   rbp
    4837:	48 89 e5             	mov    rbp,rsp
    483a:	48 83 ec 70          	sub    rsp,0x70
    483e:	48 89 7d a8          	mov    QWORD PTR [rbp-0x58],rdi
    4842:	89 75 a4             	mov    DWORD PTR [rbp-0x5c],esi
    4845:	89 c8                	mov    eax,ecx
    4847:	4c 89 45 90          	mov    QWORD PTR [rbp-0x70],r8
    484b:	88 55 a0             	mov    BYTE PTR [rbp-0x60],dl
    484e:	88 45 9c             	mov    BYTE PTR [rbp-0x64],al
    4851:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
    4858:	00 
    4859:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
    4860:	00 
    4861:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
    4868:	00 
    4869:	48 c7 45 c0 00 00 00 	mov    QWORD PTR [rbp-0x40],0x0
    4870:	00 
    4871:	c7 45 b4 f8 ff ff ff 	mov    DWORD PTR [rbp-0x4c],0xfffffff8
    4878:	48 83 7d a8 00       	cmp    QWORD PTR [rbp-0x58],0x0
    487d:	74 1c                	je     489b <verifiable_secret_sharing_split+0x65>
    487f:	83 7d a4 00          	cmp    DWORD PTR [rbp-0x5c],0x0
    4883:	74 16                	je     489b <verifiable_secret_sharing_split+0x65>
    4885:	48 83 7d 90 00       	cmp    QWORD PTR [rbp-0x70],0x0
    488a:	74 0f                	je     489b <verifiable_secret_sharing_split+0x65>
    488c:	80 7d a0 00          	cmp    BYTE PTR [rbp-0x60],0x0
    4890:	74 09                	je     489b <verifiable_secret_sharing_split+0x65>
    4892:	0f b6 45 a0          	movzx  eax,BYTE PTR [rbp-0x60]
    4896:	3a 45 9c             	cmp    al,BYTE PTR [rbp-0x64]
    4899:	76 0a                	jbe    48a5 <verifiable_secret_sharing_split+0x6f>
    489b:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    48a0:	e9 6d 02 00 00       	jmp    4b12 <verifiable_secret_sharing_split+0x2dc>
    48a5:	e8 26 ce ff ff       	call   16d0 <BN_CTX_new@plt>
    48aa:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
    48ae:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
    48b3:	0f 84 ff 01 00 00    	je     4ab8 <verifiable_secret_sharing_split+0x282>
    48b9:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    48bd:	48 89 c7             	mov    rdi,rax
    48c0:	e8 3b cf ff ff       	call   1800 <BN_CTX_start@plt>
    48c5:	0f b6 55 9c          	movzx  edx,BYTE PTR [rbp-0x64]
    48c9:	0f b6 45 a0          	movzx  eax,BYTE PTR [rbp-0x60]
    48cd:	0f af c2             	imul   eax,edx
    48d0:	48 98                	cdqe   
    48d2:	be 08 00 00 00       	mov    esi,0x8
    48d7:	48 89 c7             	mov    rdi,rax
    48da:	e8 41 ce ff ff       	call   1720 <calloc@plt>
    48df:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
    48e3:	48 83 7d b8 00       	cmp    QWORD PTR [rbp-0x48],0x0
    48e8:	0f 84 cd 01 00 00    	je     4abb <verifiable_secret_sharing_split+0x285>
    48ee:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    48f2:	48 89 c7             	mov    rdi,rax
    48f5:	e8 76 ce ff ff       	call   1770 <BN_CTX_get@plt>
    48fa:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
    48fe:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
    4903:	0f 84 b5 01 00 00    	je     4abe <verifiable_secret_sharing_split+0x288>
    4909:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    490d:	be 01 00 00 00       	mov    esi,0x1
    4912:	48 89 c7             	mov    rdi,rax
    4915:	e8 56 cc ff ff       	call   1570 <BN_set_word@plt>
    491a:	0f b6 45 9c          	movzx  eax,BYTE PTR [rbp-0x64]
    491e:	be 08 00 00 00       	mov    esi,0x8
    4923:	48 89 c7             	mov    rdi,rax
    4926:	e8 f5 cd ff ff       	call   1720 <calloc@plt>
    492b:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
    492f:	48 83 7d c0 00       	cmp    QWORD PTR [rbp-0x40],0x0
    4934:	0f 84 87 01 00 00    	je     4ac1 <verifiable_secret_sharing_split+0x28b>
    493a:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
    493e:	48 c7 00 01 00 00 00 	mov    QWORD PTR [rax],0x1
    4945:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
    494c:	00 
    494d:	eb 1f                	jmp    496e <verifiable_secret_sharing_split+0x138>
    494f:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    4953:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
    495a:	00 
    495b:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
    495f:	48 01 c2             	add    rdx,rax
    4962:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    4966:	48 89 02             	mov    QWORD PTR [rdx],rax
    4969:	48 83 45 c8 01       	add    QWORD PTR [rbp-0x38],0x1
    496e:	0f b6 45 a0          	movzx  eax,BYTE PTR [rbp-0x60]
    4972:	48 39 45 c8          	cmp    QWORD PTR [rbp-0x38],rax
    4976:	72 d7                	jb     494f <verifiable_secret_sharing_split+0x119>
    4978:	48 c7 45 d0 01 00 00 	mov    QWORD PTR [rbp-0x30],0x1
    497f:	00 
    4980:	e9 f1 00 00 00       	jmp    4a76 <verifiable_secret_sharing_split+0x240>
    4985:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    4989:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
    498d:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
    4991:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
    4998:	00 
    4999:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
    499d:	48 01 d0             	add    rax,rdx
    49a0:	48 8b 55 d0          	mov    rdx,QWORD PTR [rbp-0x30]
    49a4:	48 83 c2 01          	add    rdx,0x1
    49a8:	48 89 10             	mov    QWORD PTR [rax],rdx
    49ab:	0f b6 45 a0          	movzx  eax,BYTE PTR [rbp-0x60]
    49af:	48 0f af 45 d0       	imul   rax,QWORD PTR [rbp-0x30]
    49b4:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
    49bb:	00 
    49bc:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
    49c0:	48 01 c2             	add    rdx,rax
    49c3:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    49c7:	48 89 02             	mov    QWORD PTR [rdx],rax
    49ca:	48 c7 45 e0 01 00 00 	mov    QWORD PTR [rbp-0x20],0x1
    49d1:	00 
    49d2:	e9 8c 00 00 00       	jmp    4a63 <verifiable_secret_sharing_split+0x22d>
    49d7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    49db:	48 89 c7             	mov    rdi,rax
    49de:	e8 8d cd ff ff       	call   1770 <BN_CTX_get@plt>
    49e3:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    49e7:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    49ec:	0f 84 d2 00 00 00    	je     4ac4 <verifiable_secret_sharing_split+0x28e>
    49f2:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
    49f6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    49fa:	48 89 d6             	mov    rsi,rdx
    49fd:	48 89 c7             	mov    rdi,rax
    4a00:	e8 ab cb ff ff       	call   15b0 <BN_copy@plt>
    4a05:	48 85 c0             	test   rax,rax
    4a08:	0f 84 b9 00 00 00    	je     4ac7 <verifiable_secret_sharing_split+0x291>
    4a0e:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
    4a12:	48 8d 50 01          	lea    rdx,[rax+0x1]
    4a16:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    4a1a:	48 89 d6             	mov    rsi,rdx
    4a1d:	48 89 c7             	mov    rdi,rax
    4a20:	e8 db ca ff ff       	call   1500 <BN_mul_word@plt>
    4a25:	85 c0                	test   eax,eax
    4a27:	0f 84 9d 00 00 00    	je     4aca <verifiable_secret_sharing_split+0x294>
    4a2d:	0f b6 45 a0          	movzx  eax,BYTE PTR [rbp-0x60]
    4a31:	48 0f af 45 d0       	imul   rax,QWORD PTR [rbp-0x30]
    4a36:	48 89 c2             	mov    rdx,rax
    4a39:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
    4a3d:	48 01 d0             	add    rax,rdx
    4a40:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
    4a47:	00 
    4a48:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
    4a4c:	48 01 c2             	add    rdx,rax
    4a4f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    4a53:	48 89 02             	mov    QWORD PTR [rdx],rax
    4a56:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    4a5a:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
    4a5e:	48 83 45 e0 01       	add    QWORD PTR [rbp-0x20],0x1
    4a63:	0f b6 45 a0          	movzx  eax,BYTE PTR [rbp-0x60]
    4a67:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
    4a6b:	0f 82 66 ff ff ff    	jb     49d7 <verifiable_secret_sharing_split+0x1a1>
    4a71:	48 83 45 d0 01       	add    QWORD PTR [rbp-0x30],0x1
    4a76:	0f b6 45 9c          	movzx  eax,BYTE PTR [rbp-0x64]
    4a7a:	48 39 45 d0          	cmp    QWORD PTR [rbp-0x30],rax
    4a7e:	0f 82 01 ff ff ff    	jb     4985 <verifiable_secret_sharing_split+0x14f>
    4a84:	0f b6 4d 9c          	movzx  ecx,BYTE PTR [rbp-0x64]
    4a88:	0f b6 55 a0          	movzx  edx,BYTE PTR [rbp-0x60]
    4a8c:	4c 8b 45 90          	mov    r8,QWORD PTR [rbp-0x70]
    4a90:	48 8b 7d b8          	mov    rdi,QWORD PTR [rbp-0x48]
    4a94:	8b 75 a4             	mov    esi,DWORD PTR [rbp-0x5c]
    4a97:	48 8b 45 a8          	mov    rax,QWORD PTR [rbp-0x58]
    4a9b:	ff 75 e8             	push   QWORD PTR [rbp-0x18]
    4a9e:	ff 75 c0             	push   QWORD PTR [rbp-0x40]
    4aa1:	4d 89 c1             	mov    r9,r8
    4aa4:	49 89 f8             	mov    r8,rdi
    4aa7:	48 89 c7             	mov    rdi,rax
    4aaa:	e8 53 fb ff ff       	call   4602 <verifiable_secret_sharing_split_impl>
    4aaf:	48 83 c4 10          	add    rsp,0x10
    4ab3:	89 45 b4             	mov    DWORD PTR [rbp-0x4c],eax
    4ab6:	eb 13                	jmp    4acb <verifiable_secret_sharing_split+0x295>
    4ab8:	90                   	nop
    4ab9:	eb 10                	jmp    4acb <verifiable_secret_sharing_split+0x295>
    4abb:	90                   	nop
    4abc:	eb 0d                	jmp    4acb <verifiable_secret_sharing_split+0x295>
    4abe:	90                   	nop
    4abf:	eb 0a                	jmp    4acb <verifiable_secret_sharing_split+0x295>
    4ac1:	90                   	nop
    4ac2:	eb 07                	jmp    4acb <verifiable_secret_sharing_split+0x295>
    4ac4:	90                   	nop
    4ac5:	eb 04                	jmp    4acb <verifiable_secret_sharing_split+0x295>
    4ac7:	90                   	nop
    4ac8:	eb 01                	jmp    4acb <verifiable_secret_sharing_split+0x295>
    4aca:	90                   	nop
    4acb:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
    4ad0:	74 18                	je     4aea <verifiable_secret_sharing_split+0x2b4>
    4ad2:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    4ad6:	48 89 c7             	mov    rdi,rax
    4ad9:	e8 f2 cc ff ff       	call   17d0 <BN_CTX_end@plt>
    4ade:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    4ae2:	48 89 c7             	mov    rdi,rax
    4ae5:	e8 e6 c9 ff ff       	call   14d0 <BN_CTX_free@plt>
    4aea:	48 83 7d b8 00       	cmp    QWORD PTR [rbp-0x48],0x0
    4aef:	74 0c                	je     4afd <verifiable_secret_sharing_split+0x2c7>
    4af1:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
    4af5:	48 89 c7             	mov    rdi,rax
    4af8:	e8 23 cb ff ff       	call   1620 <free@plt>
    4afd:	83 7d b4 00          	cmp    DWORD PTR [rbp-0x4c],0x0
    4b01:	74 0c                	je     4b0f <verifiable_secret_sharing_split+0x2d9>
    4b03:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
    4b07:	48 89 c7             	mov    rdi,rax
    4b0a:	e8 11 cb ff ff       	call   1620 <free@plt>
    4b0f:	8b 45 b4             	mov    eax,DWORD PTR [rbp-0x4c]
    4b12:	c9                   	leave  
    4b13:	c3                   	ret    

0000000000004b14 <verifiable_secret_sharing_split_with_custom_ids>:
    4b14:	55                   	push   rbp
    4b15:	48 89 e5             	mov    rbp,rsp
    4b18:	48 81 ec 90 00 00 00 	sub    rsp,0x90
    4b1f:	48 89 7d 98          	mov    QWORD PTR [rbp-0x68],rdi
    4b23:	89 75 94             	mov    DWORD PTR [rbp-0x6c],esi
    4b26:	89 c8                	mov    eax,ecx
    4b28:	4c 89 45 80          	mov    QWORD PTR [rbp-0x80],r8
    4b2c:	4c 89 8d 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],r9
    4b33:	88 55 90             	mov    BYTE PTR [rbp-0x70],dl
    4b36:	88 45 8c             	mov    BYTE PTR [rbp-0x74],al
    4b39:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
    4b40:	00 
    4b41:	48 c7 45 b0 00 00 00 	mov    QWORD PTR [rbp-0x50],0x0
    4b48:	00 
    4b49:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
    4b50:	00 
    4b51:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
    4b58:	00 
    4b59:	c7 45 ac f8 ff ff ff 	mov    DWORD PTR [rbp-0x54],0xfffffff8
    4b60:	48 83 7d 98 00       	cmp    QWORD PTR [rbp-0x68],0x0
    4b65:	74 26                	je     4b8d <verifiable_secret_sharing_split_with_custom_ids+0x79>
    4b67:	83 7d 94 00          	cmp    DWORD PTR [rbp-0x6c],0x0
    4b6b:	74 20                	je     4b8d <verifiable_secret_sharing_split_with_custom_ids+0x79>
    4b6d:	48 83 bd 78 ff ff ff 	cmp    QWORD PTR [rbp-0x88],0x0
    4b74:	00 
    4b75:	74 16                	je     4b8d <verifiable_secret_sharing_split_with_custom_ids+0x79>
    4b77:	80 7d 90 00          	cmp    BYTE PTR [rbp-0x70],0x0
    4b7b:	74 10                	je     4b8d <verifiable_secret_sharing_split_with_custom_ids+0x79>
    4b7d:	0f b6 45 90          	movzx  eax,BYTE PTR [rbp-0x70]
    4b81:	3a 45 8c             	cmp    al,BYTE PTR [rbp-0x74]
    4b84:	77 07                	ja     4b8d <verifiable_secret_sharing_split_with_custom_ids+0x79>
    4b86:	48 83 7d 80 00       	cmp    QWORD PTR [rbp-0x80],0x0
    4b8b:	75 0a                	jne    4b97 <verifiable_secret_sharing_split_with_custom_ids+0x83>
    4b8d:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    4b92:	e9 e2 02 00 00       	jmp    4e79 <verifiable_secret_sharing_split_with_custom_ids+0x365>
    4b97:	e8 34 cb ff ff       	call   16d0 <BN_CTX_new@plt>
    4b9c:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
    4ba0:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
    4ba5:	0f 84 74 02 00 00    	je     4e1f <verifiable_secret_sharing_split_with_custom_ids+0x30b>
    4bab:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    4baf:	48 89 c7             	mov    rdi,rax
    4bb2:	e8 49 cc ff ff       	call   1800 <BN_CTX_start@plt>
    4bb7:	0f b6 55 8c          	movzx  edx,BYTE PTR [rbp-0x74]
    4bbb:	0f b6 45 90          	movzx  eax,BYTE PTR [rbp-0x70]
    4bbf:	0f af c2             	imul   eax,edx
    4bc2:	48 98                	cdqe   
    4bc4:	be 08 00 00 00       	mov    esi,0x8
    4bc9:	48 89 c7             	mov    rdi,rax
    4bcc:	e8 4f cb ff ff       	call   1720 <calloc@plt>
    4bd1:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
    4bd5:	48 83 7d b0 00       	cmp    QWORD PTR [rbp-0x50],0x0
    4bda:	0f 84 42 02 00 00    	je     4e22 <verifiable_secret_sharing_split_with_custom_ids+0x30e>
    4be0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    4be4:	48 89 c7             	mov    rdi,rax
    4be7:	e8 84 cb ff ff       	call   1770 <BN_CTX_get@plt>
    4bec:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
    4bf0:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
    4bf5:	0f 84 2a 02 00 00    	je     4e25 <verifiable_secret_sharing_split_with_custom_ids+0x311>
    4bfb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    4bff:	be 01 00 00 00       	mov    esi,0x1
    4c04:	48 89 c7             	mov    rdi,rax
    4c07:	e8 64 c9 ff ff       	call   1570 <BN_set_word@plt>
    4c0c:	0f b6 45 8c          	movzx  eax,BYTE PTR [rbp-0x74]
    4c10:	be 08 00 00 00       	mov    esi,0x8
    4c15:	48 89 c7             	mov    rdi,rax
    4c18:	e8 03 cb ff ff       	call   1720 <calloc@plt>
    4c1d:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
    4c21:	48 83 7d b8 00       	cmp    QWORD PTR [rbp-0x48],0x0
    4c26:	0f 84 fc 01 00 00    	je     4e28 <verifiable_secret_sharing_split_with_custom_ids+0x314>
    4c2c:	0f b6 45 8c          	movzx  eax,BYTE PTR [rbp-0x74]
    4c30:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
    4c37:	00 
    4c38:	48 8b 4d 80          	mov    rcx,QWORD PTR [rbp-0x80]
    4c3c:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
    4c40:	48 89 ce             	mov    rsi,rcx
    4c43:	48 89 c7             	mov    rdi,rax
    4c46:	e8 a5 cb ff ff       	call   17f0 <memcpy@plt>
    4c4b:	48 c7 45 c0 00 00 00 	mov    QWORD PTR [rbp-0x40],0x0
    4c52:	00 
    4c53:	e9 86 00 00 00       	jmp    4cde <verifiable_secret_sharing_split_with_custom_ids+0x1ca>
    4c58:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
    4c5c:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
    4c63:	00 
    4c64:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
    4c68:	48 01 d0             	add    rax,rdx
    4c6b:	48 8b 00             	mov    rax,QWORD PTR [rax]
    4c6e:	48 85 c0             	test   rax,rax
    4c71:	75 0c                	jne    4c7f <verifiable_secret_sharing_split_with_custom_ids+0x16b>
    4c73:	c7 45 ac fa ff ff ff 	mov    DWORD PTR [rbp-0x54],0xfffffffa
    4c7a:	e9 b3 01 00 00       	jmp    4e32 <verifiable_secret_sharing_split_with_custom_ids+0x31e>
    4c7f:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
    4c83:	48 83 c0 01          	add    rax,0x1
    4c87:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
    4c8b:	eb 42                	jmp    4ccf <verifiable_secret_sharing_split_with_custom_ids+0x1bb>
    4c8d:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
    4c91:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
    4c98:	00 
    4c99:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
    4c9d:	48 01 d0             	add    rax,rdx
    4ca0:	48 8b 10             	mov    rdx,QWORD PTR [rax]
    4ca3:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    4ca7:	48 8d 0c c5 00 00 00 	lea    rcx,[rax*8+0x0]
    4cae:	00 
    4caf:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
    4cb3:	48 01 c8             	add    rax,rcx
    4cb6:	48 8b 00             	mov    rax,QWORD PTR [rax]
    4cb9:	48 39 c2             	cmp    rdx,rax
    4cbc:	75 0c                	jne    4cca <verifiable_secret_sharing_split_with_custom_ids+0x1b6>
    4cbe:	c7 45 ac fa ff ff ff 	mov    DWORD PTR [rbp-0x54],0xfffffffa
    4cc5:	e9 68 01 00 00       	jmp    4e32 <verifiable_secret_sharing_split_with_custom_ids+0x31e>
    4cca:	48 83 45 c8 01       	add    QWORD PTR [rbp-0x38],0x1
    4ccf:	0f b6 45 8c          	movzx  eax,BYTE PTR [rbp-0x74]
    4cd3:	48 39 45 c8          	cmp    QWORD PTR [rbp-0x38],rax
    4cd7:	72 b4                	jb     4c8d <verifiable_secret_sharing_split_with_custom_ids+0x179>
    4cd9:	48 83 45 c0 01       	add    QWORD PTR [rbp-0x40],0x1
    4cde:	0f b6 45 8c          	movzx  eax,BYTE PTR [rbp-0x74]
    4ce2:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
    4ce6:	0f 82 6c ff ff ff    	jb     4c58 <verifiable_secret_sharing_split_with_custom_ids+0x144>
    4cec:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
    4cf3:	00 
    4cf4:	e9 e1 00 00 00       	jmp    4dda <verifiable_secret_sharing_split_with_custom_ids+0x2c6>
    4cf9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    4cfd:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
    4d01:	0f b6 45 90          	movzx  eax,BYTE PTR [rbp-0x70]
    4d05:	48 0f af 45 d0       	imul   rax,QWORD PTR [rbp-0x30]
    4d0a:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
    4d11:	00 
    4d12:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
    4d16:	48 01 c2             	add    rdx,rax
    4d19:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    4d1d:	48 89 02             	mov    QWORD PTR [rdx],rax
    4d20:	48 c7 45 e0 01 00 00 	mov    QWORD PTR [rbp-0x20],0x1
    4d27:	00 
    4d28:	e9 9a 00 00 00       	jmp    4dc7 <verifiable_secret_sharing_split_with_custom_ids+0x2b3>
    4d2d:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    4d31:	48 89 c7             	mov    rdi,rax
    4d34:	e8 37 ca ff ff       	call   1770 <BN_CTX_get@plt>
    4d39:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    4d3d:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    4d42:	0f 84 e3 00 00 00    	je     4e2b <verifiable_secret_sharing_split_with_custom_ids+0x317>
    4d48:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
    4d4c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    4d50:	48 89 d6             	mov    rsi,rdx
    4d53:	48 89 c7             	mov    rdi,rax
    4d56:	e8 55 c8 ff ff       	call   15b0 <BN_copy@plt>
    4d5b:	48 85 c0             	test   rax,rax
    4d5e:	0f 84 ca 00 00 00    	je     4e2e <verifiable_secret_sharing_split_with_custom_ids+0x31a>
    4d64:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
    4d68:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
    4d6f:	00 
    4d70:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
    4d74:	48 01 d0             	add    rax,rdx
    4d77:	48 8b 10             	mov    rdx,QWORD PTR [rax]
    4d7a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    4d7e:	48 89 d6             	mov    rsi,rdx
    4d81:	48 89 c7             	mov    rdi,rax
    4d84:	e8 77 c7 ff ff       	call   1500 <BN_mul_word@plt>
    4d89:	85 c0                	test   eax,eax
    4d8b:	0f 84 a0 00 00 00    	je     4e31 <verifiable_secret_sharing_split_with_custom_ids+0x31d>
    4d91:	0f b6 45 90          	movzx  eax,BYTE PTR [rbp-0x70]
    4d95:	48 0f af 45 d0       	imul   rax,QWORD PTR [rbp-0x30]
    4d9a:	48 89 c2             	mov    rdx,rax
    4d9d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
    4da1:	48 01 d0             	add    rax,rdx
    4da4:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
    4dab:	00 
    4dac:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
    4db0:	48 01 c2             	add    rdx,rax
    4db3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    4db7:	48 89 02             	mov    QWORD PTR [rdx],rax
    4dba:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    4dbe:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
    4dc2:	48 83 45 e0 01       	add    QWORD PTR [rbp-0x20],0x1
    4dc7:	0f b6 45 90          	movzx  eax,BYTE PTR [rbp-0x70]
    4dcb:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
    4dcf:	0f 82 58 ff ff ff    	jb     4d2d <verifiable_secret_sharing_split_with_custom_ids+0x219>
    4dd5:	48 83 45 d0 01       	add    QWORD PTR [rbp-0x30],0x1
    4dda:	0f b6 45 8c          	movzx  eax,BYTE PTR [rbp-0x74]
    4dde:	48 39 45 d0          	cmp    QWORD PTR [rbp-0x30],rax
    4de2:	0f 82 11 ff ff ff    	jb     4cf9 <verifiable_secret_sharing_split_with_custom_ids+0x1e5>
    4de8:	0f b6 4d 8c          	movzx  ecx,BYTE PTR [rbp-0x74]
    4dec:	0f b6 55 90          	movzx  edx,BYTE PTR [rbp-0x70]
    4df0:	4c 8b 85 78 ff ff ff 	mov    r8,QWORD PTR [rbp-0x88]
    4df7:	48 8b 7d b0          	mov    rdi,QWORD PTR [rbp-0x50]
    4dfb:	8b 75 94             	mov    esi,DWORD PTR [rbp-0x6c]
    4dfe:	48 8b 45 98          	mov    rax,QWORD PTR [rbp-0x68]
    4e02:	ff 75 e8             	push   QWORD PTR [rbp-0x18]
    4e05:	ff 75 b8             	push   QWORD PTR [rbp-0x48]
    4e08:	4d 89 c1             	mov    r9,r8
    4e0b:	49 89 f8             	mov    r8,rdi
    4e0e:	48 89 c7             	mov    rdi,rax
    4e11:	e8 ec f7 ff ff       	call   4602 <verifiable_secret_sharing_split_impl>
    4e16:	48 83 c4 10          	add    rsp,0x10
    4e1a:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
    4e1d:	eb 13                	jmp    4e32 <verifiable_secret_sharing_split_with_custom_ids+0x31e>
    4e1f:	90                   	nop
    4e20:	eb 10                	jmp    4e32 <verifiable_secret_sharing_split_with_custom_ids+0x31e>
    4e22:	90                   	nop
    4e23:	eb 0d                	jmp    4e32 <verifiable_secret_sharing_split_with_custom_ids+0x31e>
    4e25:	90                   	nop
    4e26:	eb 0a                	jmp    4e32 <verifiable_secret_sharing_split_with_custom_ids+0x31e>
    4e28:	90                   	nop
    4e29:	eb 07                	jmp    4e32 <verifiable_secret_sharing_split_with_custom_ids+0x31e>
    4e2b:	90                   	nop
    4e2c:	eb 04                	jmp    4e32 <verifiable_secret_sharing_split_with_custom_ids+0x31e>
    4e2e:	90                   	nop
    4e2f:	eb 01                	jmp    4e32 <verifiable_secret_sharing_split_with_custom_ids+0x31e>
    4e31:	90                   	nop
    4e32:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
    4e37:	74 18                	je     4e51 <verifiable_secret_sharing_split_with_custom_ids+0x33d>
    4e39:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    4e3d:	48 89 c7             	mov    rdi,rax
    4e40:	e8 8b c9 ff ff       	call   17d0 <BN_CTX_end@plt>
    4e45:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    4e49:	48 89 c7             	mov    rdi,rax
    4e4c:	e8 7f c6 ff ff       	call   14d0 <BN_CTX_free@plt>
    4e51:	48 83 7d b0 00       	cmp    QWORD PTR [rbp-0x50],0x0
    4e56:	74 0c                	je     4e64 <verifiable_secret_sharing_split_with_custom_ids+0x350>
    4e58:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
    4e5c:	48 89 c7             	mov    rdi,rax
    4e5f:	e8 bc c7 ff ff       	call   1620 <free@plt>
    4e64:	83 7d ac 00          	cmp    DWORD PTR [rbp-0x54],0x0
    4e68:	74 0c                	je     4e76 <verifiable_secret_sharing_split_with_custom_ids+0x362>
    4e6a:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
    4e6e:	48 89 c7             	mov    rdi,rax
    4e71:	e8 aa c7 ff ff       	call   1620 <free@plt>
    4e76:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
    4e79:	c9                   	leave  
    4e7a:	c3                   	ret    

0000000000004e7b <verifiable_secret_sharing_get_share>:
    4e7b:	55                   	push   rbp
    4e7c:	48 89 e5             	mov    rbp,rsp
    4e7f:	48 83 ec 20          	sub    rsp,0x20
    4e83:	48 89 7d f8          	mov    QWORD PTR [rbp-0x8],rdi
    4e87:	89 f0                	mov    eax,esi
    4e89:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
    4e8d:	88 45 f4             	mov    BYTE PTR [rbp-0xc],al
    4e90:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    4e95:	74 07                	je     4e9e <verifiable_secret_sharing_get_share+0x23>
    4e97:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
    4e9c:	75 07                	jne    4ea5 <verifiable_secret_sharing_get_share+0x2a>
    4e9e:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    4ea3:	eb 7e                	jmp    4f23 <verifiable_secret_sharing_get_share+0xa8>
    4ea5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    4ea9:	0f b6 40 28          	movzx  eax,BYTE PTR [rax+0x28]
    4ead:	38 45 f4             	cmp    BYTE PTR [rbp-0xc],al
    4eb0:	72 07                	jb     4eb9 <verifiable_secret_sharing_get_share+0x3e>
    4eb2:	b8 fd ff ff ff       	mov    eax,0xfffffffd
    4eb7:	eb 6a                	jmp    4f23 <verifiable_secret_sharing_get_share+0xa8>
    4eb9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    4ebd:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
    4ec1:	0f b6 55 f4          	movzx  edx,BYTE PTR [rbp-0xc]
    4ec5:	48 c1 e2 05          	shl    rdx,0x5
    4ec9:	48 01 d0             	add    rax,rdx
    4ecc:	48 85 c0             	test   rax,rax
    4ecf:	75 07                	jne    4ed8 <verifiable_secret_sharing_get_share+0x5d>
    4ed1:	b8 ff ff ff ff       	mov    eax,0xffffffff
    4ed6:	eb 4b                	jmp    4f23 <verifiable_secret_sharing_get_share+0xa8>
    4ed8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    4edc:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
    4ee0:	0f b6 55 f4          	movzx  edx,BYTE PTR [rbp-0xc]
    4ee4:	48 c1 e2 03          	shl    rdx,0x3
    4ee8:	48 01 d0             	add    rax,rdx
    4eeb:	48 8b 10             	mov    rdx,QWORD PTR [rax]
    4eee:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    4ef2:	48 89 50 20          	mov    QWORD PTR [rax+0x20],rdx
    4ef6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    4efa:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
    4efe:	0f b6 55 f4          	movzx  edx,BYTE PTR [rbp-0xc]
    4f02:	48 c1 e2 05          	shl    rdx,0x5
    4f06:	48 8d 0c 10          	lea    rcx,[rax+rdx*1]
    4f0a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    4f0e:	ba 20 00 00 00       	mov    edx,0x20
    4f13:	48 89 ce             	mov    rsi,rcx
    4f16:	48 89 c7             	mov    rdi,rax
    4f19:	e8 d2 c8 ff ff       	call   17f0 <memcpy@plt>
    4f1e:	b8 00 00 00 00       	mov    eax,0x0
    4f23:	c9                   	leave  
    4f24:	c3                   	ret    

0000000000004f25 <verifiable_secret_sharing_get_share_and_proof>:
    4f25:	55                   	push   rbp
    4f26:	48 89 e5             	mov    rbp,rsp
    4f29:	48 83 ec 30          	sub    rsp,0x30
    4f2d:	48 89 7d e8          	mov    QWORD PTR [rbp-0x18],rdi
    4f31:	89 f0                	mov    eax,esi
    4f33:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
    4f37:	48 89 4d d0          	mov    QWORD PTR [rbp-0x30],rcx
    4f3b:	88 45 e4             	mov    BYTE PTR [rbp-0x1c],al
    4f3e:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
    4f43:	75 07                	jne    4f4c <verifiable_secret_sharing_get_share_and_proof+0x27>
    4f45:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    4f4a:	eb 4f                	jmp    4f9b <verifiable_secret_sharing_get_share_and_proof+0x76>
    4f4c:	0f b6 4d e4          	movzx  ecx,BYTE PTR [rbp-0x1c]
    4f50:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
    4f54:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    4f58:	89 ce                	mov    esi,ecx
    4f5a:	48 89 c7             	mov    rdi,rax
    4f5d:	e8 19 ff ff ff       	call   4e7b <verifiable_secret_sharing_get_share>
    4f62:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
    4f65:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
    4f69:	75 2d                	jne    4f98 <verifiable_secret_sharing_get_share_and_proof+0x73>
    4f6b:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    4f6f:	48 8b 48 18          	mov    rcx,QWORD PTR [rax+0x18]
    4f73:	0f b6 55 e4          	movzx  edx,BYTE PTR [rbp-0x1c]
    4f77:	48 89 d0             	mov    rax,rdx
    4f7a:	48 c1 e0 05          	shl    rax,0x5
    4f7e:	48 01 d0             	add    rax,rdx
    4f81:	48 01 c1             	add    rcx,rax
    4f84:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
    4f88:	ba 21 00 00 00       	mov    edx,0x21
    4f8d:	48 89 ce             	mov    rsi,rcx
    4f90:	48 89 c7             	mov    rdi,rax
    4f93:	e8 58 c8 ff ff       	call   17f0 <memcpy@plt>
    4f98:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
    4f9b:	c9                   	leave  
    4f9c:	c3                   	ret    

0000000000004f9d <verifiable_secret_sharing_get_shares_commitment>:
    4f9d:	55                   	push   rbp
    4f9e:	48 89 e5             	mov    rbp,rsp
    4fa1:	48 83 ec 30          	sub    rsp,0x30
    4fa5:	48 89 7d d8          	mov    QWORD PTR [rbp-0x28],rdi
    4fa9:	48 89 75 d0          	mov    QWORD PTR [rbp-0x30],rsi
    4fad:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
    4fb4:	00 
    4fb5:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
    4fba:	74 07                	je     4fc3 <verifiable_secret_sharing_get_shares_commitment+0x26>
    4fbc:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
    4fc1:	75 0a                	jne    4fcd <verifiable_secret_sharing_get_shares_commitment+0x30>
    4fc3:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    4fc8:	e9 ce 00 00 00       	jmp    509b <verifiable_secret_sharing_get_shares_commitment+0xfe>
    4fcd:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    4fd1:	0f b6 40 28          	movzx  eax,BYTE PTR [rax+0x28]
    4fd5:	0f b6 d0             	movzx  edx,al
    4fd8:	48 89 d0             	mov    rax,rdx
    4fdb:	48 c1 e0 05          	shl    rax,0x5
    4fdf:	48 01 d0             	add    rax,rdx
    4fe2:	48 89 c7             	mov    rdi,rax
    4fe5:	e8 76 c5 ff ff       	call   1560 <malloc@plt>
    4fea:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    4fee:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    4ff3:	75 0a                	jne    4fff <verifiable_secret_sharing_get_shares_commitment+0x62>
    4ff5:	b8 f8 ff ff ff       	mov    eax,0xfffffff8
    4ffa:	e9 9c 00 00 00       	jmp    509b <verifiable_secret_sharing_get_shares_commitment+0xfe>
    4fff:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
    5006:	00 
    5007:	eb 43                	jmp    504c <verifiable_secret_sharing_get_shares_commitment+0xaf>
    5009:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    500d:	48 8b 48 18          	mov    rcx,QWORD PTR [rax+0x18]
    5011:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
    5015:	48 89 d0             	mov    rax,rdx
    5018:	48 c1 e0 05          	shl    rax,0x5
    501c:	48 01 d0             	add    rax,rdx
    501f:	48 01 c1             	add    rcx,rax
    5022:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
    5026:	48 89 d0             	mov    rax,rdx
    5029:	48 c1 e0 05          	shl    rax,0x5
    502d:	48 01 c2             	add    rdx,rax
    5030:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    5034:	48 01 d0             	add    rax,rdx
    5037:	ba 21 00 00 00       	mov    edx,0x21
    503c:	48 89 ce             	mov    rsi,rcx
    503f:	48 89 c7             	mov    rdi,rax
    5042:	e8 a9 c7 ff ff       	call   17f0 <memcpy@plt>
    5047:	48 83 45 f0 01       	add    QWORD PTR [rbp-0x10],0x1
    504c:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    5050:	0f b6 40 28          	movzx  eax,BYTE PTR [rax+0x28]
    5054:	0f b6 c0             	movzx  eax,al
    5057:	48 39 45 f0          	cmp    QWORD PTR [rbp-0x10],rax
    505b:	72 ac                	jb     5009 <verifiable_secret_sharing_get_shares_commitment+0x6c>
    505d:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    5061:	0f b6 40 28          	movzx  eax,BYTE PTR [rax+0x28]
    5065:	0f b6 d0             	movzx  edx,al
    5068:	89 d0                	mov    eax,edx
    506a:	c1 e0 05             	shl    eax,0x5
    506d:	8d 0c 10             	lea    ecx,[rax+rdx*1]
    5070:	48 8b 55 d0          	mov    rdx,QWORD PTR [rbp-0x30]
    5074:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    5078:	89 ce                	mov    esi,ecx
    507a:	48 89 c7             	mov    rdi,rax
    507d:	e8 0b 25 00 00       	call   758d <commitments_create_commitment_for_data>
    5082:	89 c7                	mov    edi,eax
    5084:	e8 e0 ef ff ff       	call   4069 <from_commitments_status>
    5089:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
    508c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    5090:	48 89 c7             	mov    rdi,rax
    5093:	e8 88 c5 ff ff       	call   1620 <free@plt>
    5098:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
    509b:	c9                   	leave  
    509c:	c3                   	ret    

000000000000509d <verifiable_secret_sharing_get_numer_of_palyers>:
    509d:	55                   	push   rbp
    509e:	48 89 e5             	mov    rbp,rsp
    50a1:	48 89 7d f8          	mov    QWORD PTR [rbp-0x8],rdi
    50a5:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    50aa:	75 07                	jne    50b3 <verifiable_secret_sharing_get_numer_of_palyers+0x16>
    50ac:	b8 ff ff ff ff       	mov    eax,0xffffffff
    50b1:	eb 0b                	jmp    50be <verifiable_secret_sharing_get_numer_of_palyers+0x21>
    50b3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    50b7:	0f b6 40 28          	movzx  eax,BYTE PTR [rax+0x28]
    50bb:	0f b6 c0             	movzx  eax,al
    50be:	5d                   	pop    rbp
    50bf:	c3                   	ret    

00000000000050c0 <verifiable_secret_sharing_get_threshold>:
    50c0:	55                   	push   rbp
    50c1:	48 89 e5             	mov    rbp,rsp
    50c4:	48 89 7d f8          	mov    QWORD PTR [rbp-0x8],rdi
    50c8:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    50cd:	75 07                	jne    50d6 <verifiable_secret_sharing_get_threshold+0x16>
    50cf:	b8 ff ff ff ff       	mov    eax,0xffffffff
    50d4:	eb 0b                	jmp    50e1 <verifiable_secret_sharing_get_threshold+0x21>
    50d6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    50da:	0f b6 40 29          	movzx  eax,BYTE PTR [rax+0x29]
    50de:	0f b6 c0             	movzx  eax,al
    50e1:	5d                   	pop    rbp
    50e2:	c3                   	ret    

00000000000050e3 <verifiable_secret_sharing_get_polynom_proofs>:
    50e3:	55                   	push   rbp
    50e4:	48 89 e5             	mov    rbp,rsp
    50e7:	48 83 ec 20          	sub    rsp,0x20
    50eb:	48 89 7d f8          	mov    QWORD PTR [rbp-0x8],rdi
    50ef:	48 89 75 f0          	mov    QWORD PTR [rbp-0x10],rsi
    50f3:	89 d0                	mov    eax,edx
    50f5:	88 45 ec             	mov    BYTE PTR [rbp-0x14],al
    50f8:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    50fd:	74 14                	je     5113 <verifiable_secret_sharing_get_polynom_proofs+0x30>
    50ff:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
    5104:	74 0d                	je     5113 <verifiable_secret_sharing_get_polynom_proofs+0x30>
    5106:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    510a:	0f b6 40 29          	movzx  eax,BYTE PTR [rax+0x29]
    510e:	38 45 ec             	cmp    BYTE PTR [rbp-0x14],al
    5111:	73 07                	jae    511a <verifiable_secret_sharing_get_polynom_proofs+0x37>
    5113:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    5118:	eb 31                	jmp    514b <verifiable_secret_sharing_get_polynom_proofs+0x68>
    511a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    511e:	0f b6 40 29          	movzx  eax,BYTE PTR [rax+0x29]
    5122:	0f b6 d0             	movzx  edx,al
    5125:	48 89 d0             	mov    rax,rdx
    5128:	48 c1 e0 05          	shl    rax,0x5
    512c:	48 01 c2             	add    rdx,rax
    512f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    5133:	48 8b 48 20          	mov    rcx,QWORD PTR [rax+0x20]
    5137:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    513b:	48 89 ce             	mov    rsi,rcx
    513e:	48 89 c7             	mov    rdi,rax
    5141:	e8 aa c6 ff ff       	call   17f0 <memcpy@plt>
    5146:	b8 00 00 00 00       	mov    eax,0x0
    514b:	c9                   	leave  
    514c:	c3                   	ret    

000000000000514d <verifiable_secret_sharing_get_polynom_commitment>:
    514d:	55                   	push   rbp
    514e:	48 89 e5             	mov    rbp,rsp
    5151:	48 83 ec 30          	sub    rsp,0x30
    5155:	48 89 7d d8          	mov    QWORD PTR [rbp-0x28],rdi
    5159:	48 89 75 d0          	mov    QWORD PTR [rbp-0x30],rsi
    515d:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
    5164:	00 
    5165:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
    516a:	74 07                	je     5173 <verifiable_secret_sharing_get_polynom_commitment+0x26>
    516c:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
    5171:	75 0a                	jne    517d <verifiable_secret_sharing_get_polynom_commitment+0x30>
    5173:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    5178:	e9 ce 00 00 00       	jmp    524b <verifiable_secret_sharing_get_polynom_commitment+0xfe>
    517d:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    5181:	0f b6 40 29          	movzx  eax,BYTE PTR [rax+0x29]
    5185:	0f b6 d0             	movzx  edx,al
    5188:	48 89 d0             	mov    rax,rdx
    518b:	48 c1 e0 05          	shl    rax,0x5
    518f:	48 01 d0             	add    rax,rdx
    5192:	48 89 c7             	mov    rdi,rax
    5195:	e8 c6 c3 ff ff       	call   1560 <malloc@plt>
    519a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    519e:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    51a3:	75 0a                	jne    51af <verifiable_secret_sharing_get_polynom_commitment+0x62>
    51a5:	b8 f8 ff ff ff       	mov    eax,0xfffffff8
    51aa:	e9 9c 00 00 00       	jmp    524b <verifiable_secret_sharing_get_polynom_commitment+0xfe>
    51af:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
    51b6:	00 
    51b7:	eb 43                	jmp    51fc <verifiable_secret_sharing_get_polynom_commitment+0xaf>
    51b9:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    51bd:	48 8b 48 20          	mov    rcx,QWORD PTR [rax+0x20]
    51c1:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
    51c5:	48 89 d0             	mov    rax,rdx
    51c8:	48 c1 e0 05          	shl    rax,0x5
    51cc:	48 01 d0             	add    rax,rdx
    51cf:	48 01 c1             	add    rcx,rax
    51d2:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
    51d6:	48 89 d0             	mov    rax,rdx
    51d9:	48 c1 e0 05          	shl    rax,0x5
    51dd:	48 01 c2             	add    rdx,rax
    51e0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    51e4:	48 01 d0             	add    rax,rdx
    51e7:	ba 21 00 00 00       	mov    edx,0x21
    51ec:	48 89 ce             	mov    rsi,rcx
    51ef:	48 89 c7             	mov    rdi,rax
    51f2:	e8 f9 c5 ff ff       	call   17f0 <memcpy@plt>
    51f7:	48 83 45 f0 01       	add    QWORD PTR [rbp-0x10],0x1
    51fc:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    5200:	0f b6 40 29          	movzx  eax,BYTE PTR [rax+0x29]
    5204:	0f b6 c0             	movzx  eax,al
    5207:	48 39 45 f0          	cmp    QWORD PTR [rbp-0x10],rax
    520b:	72 ac                	jb     51b9 <verifiable_secret_sharing_get_polynom_commitment+0x6c>
    520d:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    5211:	0f b6 40 29          	movzx  eax,BYTE PTR [rax+0x29]
    5215:	0f b6 d0             	movzx  edx,al
    5218:	89 d0                	mov    eax,edx
    521a:	c1 e0 05             	shl    eax,0x5
    521d:	8d 0c 10             	lea    ecx,[rax+rdx*1]
    5220:	48 8b 55 d0          	mov    rdx,QWORD PTR [rbp-0x30]
    5224:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    5228:	89 ce                	mov    esi,ecx
    522a:	48 89 c7             	mov    rdi,rax
    522d:	e8 5b 23 00 00       	call   758d <commitments_create_commitment_for_data>
    5232:	89 c7                	mov    edi,eax
    5234:	e8 30 ee ff ff       	call   4069 <from_commitments_status>
    5239:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
    523c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    5240:	48 89 c7             	mov    rdi,rax
    5243:	e8 d8 c3 ff ff       	call   1620 <free@plt>
    5248:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
    524b:	c9                   	leave  
    524c:	c3                   	ret    

000000000000524d <lagrange_interpolate>:
    524d:	55                   	push   rbp
    524e:	48 89 e5             	mov    rbp,rsp
    5251:	48 83 ec 50          	sub    rsp,0x50
    5255:	48 89 7d d8          	mov    QWORD PTR [rbp-0x28],rdi
    5259:	89 d0                	mov    eax,edx
    525b:	48 89 4d c8          	mov    QWORD PTR [rbp-0x38],rcx
    525f:	4c 89 45 c0          	mov    QWORD PTR [rbp-0x40],r8
    5263:	4c 89 4d b8          	mov    QWORD PTR [rbp-0x48],r9
    5267:	89 f2                	mov    edx,esi
    5269:	88 55 d4             	mov    BYTE PTR [rbp-0x2c],dl
    526c:	88 45 d0             	mov    BYTE PTR [rbp-0x30],al
    526f:	c7 45 e4 00 00 00 00 	mov    DWORD PTR [rbp-0x1c],0x0
    5276:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
    527d:	00 
    527e:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
    5285:	00 
    5286:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
    528d:	00 
    528e:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
    5292:	48 89 c7             	mov    rdi,rax
    5295:	e8 66 c5 ff ff       	call   1800 <BN_CTX_start@plt>
    529a:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
    529e:	48 89 c7             	mov    rdi,rax
    52a1:	e8 ca c4 ff ff       	call   1770 <BN_CTX_get@plt>
    52a6:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
    52aa:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
    52ae:	48 89 c7             	mov    rdi,rax
    52b1:	e8 ba c4 ff ff       	call   1770 <BN_CTX_get@plt>
    52b6:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
    52ba:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
    52be:	48 89 c7             	mov    rdi,rax
    52c1:	e8 aa c4 ff ff       	call   1770 <BN_CTX_get@plt>
    52c6:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    52ca:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
    52cf:	0f 84 5a 01 00 00    	je     542f <lagrange_interpolate+0x1e2>
    52d5:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
    52da:	0f 84 4f 01 00 00    	je     542f <lagrange_interpolate+0x1e2>
    52e0:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    52e5:	0f 84 44 01 00 00    	je     542f <lagrange_interpolate+0x1e2>
    52eb:	0f b6 55 d0          	movzx  edx,BYTE PTR [rbp-0x30]
    52ef:	48 89 d0             	mov    rax,rdx
    52f2:	48 c1 e0 02          	shl    rax,0x2
    52f6:	48 01 d0             	add    rax,rdx
    52f9:	48 c1 e0 03          	shl    rax,0x3
    52fd:	48 89 c2             	mov    rdx,rax
    5300:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    5304:	48 01 d0             	add    rax,rdx
    5307:	48 8b 50 20          	mov    rdx,QWORD PTR [rax+0x20]
    530b:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    530f:	48 89 d6             	mov    rsi,rdx
    5312:	48 89 c7             	mov    rdi,rax
    5315:	e8 56 c2 ff ff       	call   1570 <BN_set_word@plt>
    531a:	85 c0                	test   eax,eax
    531c:	0f 84 10 01 00 00    	je     5432 <lagrange_interpolate+0x1e5>
    5322:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    5326:	be 01 00 00 00       	mov    esi,0x1
    532b:	48 89 c7             	mov    rdi,rax
    532e:	e8 3d c2 ff ff       	call   1570 <BN_set_word@plt>
    5333:	85 c0                	test   eax,eax
    5335:	0f 84 fa 00 00 00    	je     5435 <lagrange_interpolate+0x1e8>
    533b:	c6 45 e3 00          	mov    BYTE PTR [rbp-0x1d],0x0
    533f:	e9 d5 00 00 00       	jmp    5419 <lagrange_interpolate+0x1cc>
    5344:	0f b6 45 e3          	movzx  eax,BYTE PTR [rbp-0x1d]
    5348:	3a 45 d0             	cmp    al,BYTE PTR [rbp-0x30]
    534b:	0f 84 c3 00 00 00    	je     5414 <lagrange_interpolate+0x1c7>
    5351:	0f b6 55 e3          	movzx  edx,BYTE PTR [rbp-0x1d]
    5355:	48 89 d0             	mov    rax,rdx
    5358:	48 c1 e0 02          	shl    rax,0x2
    535c:	48 01 d0             	add    rax,rdx
    535f:	48 c1 e0 03          	shl    rax,0x3
    5363:	48 89 c2             	mov    rdx,rax
    5366:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    536a:	48 01 d0             	add    rax,rdx
    536d:	48 8b 50 20          	mov    rdx,QWORD PTR [rax+0x20]
    5371:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    5375:	48 89 d6             	mov    rsi,rdx
    5378:	48 89 c7             	mov    rdi,rax
    537b:	e8 f0 c1 ff ff       	call   1570 <BN_set_word@plt>
    5380:	85 c0                	test   eax,eax
    5382:	0f 84 b0 00 00 00    	je     5438 <lagrange_interpolate+0x1eb>
    5388:	48 8b 7d b8          	mov    rdi,QWORD PTR [rbp-0x48]
    538c:	48 8b 4d c0          	mov    rcx,QWORD PTR [rbp-0x40]
    5390:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
    5394:	48 8b 75 f0          	mov    rsi,QWORD PTR [rbp-0x10]
    5398:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    539c:	49 89 f8             	mov    r8,rdi
    539f:	48 89 c7             	mov    rdi,rax
    53a2:	e8 29 c2 ff ff       	call   15d0 <BN_mod_sub@plt>
    53a7:	85 c0                	test   eax,eax
    53a9:	0f 84 8c 00 00 00    	je     543b <lagrange_interpolate+0x1ee>
    53af:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
    53b3:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
    53b7:	48 8b 75 f8          	mov    rsi,QWORD PTR [rbp-0x8]
    53bb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    53bf:	48 89 c7             	mov    rdi,rax
    53c2:	e8 19 c1 ff ff       	call   14e0 <BN_mod_inverse@plt>
    53c7:	48 85 c0             	test   rax,rax
    53ca:	74 72                	je     543e <lagrange_interpolate+0x1f1>
    53cc:	48 8b 7d b8          	mov    rdi,QWORD PTR [rbp-0x48]
    53d0:	48 8b 4d c0          	mov    rcx,QWORD PTR [rbp-0x40]
    53d4:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
    53d8:	48 8b 75 f8          	mov    rsi,QWORD PTR [rbp-0x8]
    53dc:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    53e0:	49 89 f8             	mov    r8,rdi
    53e3:	48 89 c7             	mov    rdi,rax
    53e6:	e8 d5 c0 ff ff       	call   14c0 <BN_mod_mul@plt>
    53eb:	85 c0                	test   eax,eax
    53ed:	74 52                	je     5441 <lagrange_interpolate+0x1f4>
    53ef:	48 8b 7d b8          	mov    rdi,QWORD PTR [rbp-0x48]
    53f3:	48 8b 4d c0          	mov    rcx,QWORD PTR [rbp-0x40]
    53f7:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
    53fb:	48 8b 75 c8          	mov    rsi,QWORD PTR [rbp-0x38]
    53ff:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    5403:	49 89 f8             	mov    r8,rdi
    5406:	48 89 c7             	mov    rdi,rax
    5409:	e8 b2 c0 ff ff       	call   14c0 <BN_mod_mul@plt>
    540e:	85 c0                	test   eax,eax
    5410:	74 32                	je     5444 <lagrange_interpolate+0x1f7>
    5412:	eb 01                	jmp    5415 <lagrange_interpolate+0x1c8>
    5414:	90                   	nop
    5415:	80 45 e3 01          	add    BYTE PTR [rbp-0x1d],0x1
    5419:	0f b6 45 e3          	movzx  eax,BYTE PTR [rbp-0x1d]
    541d:	3a 45 d4             	cmp    al,BYTE PTR [rbp-0x2c]
    5420:	0f 82 1e ff ff ff    	jb     5344 <lagrange_interpolate+0xf7>
    5426:	c7 45 e4 01 00 00 00 	mov    DWORD PTR [rbp-0x1c],0x1
    542d:	eb 16                	jmp    5445 <lagrange_interpolate+0x1f8>
    542f:	90                   	nop
    5430:	eb 13                	jmp    5445 <lagrange_interpolate+0x1f8>
    5432:	90                   	nop
    5433:	eb 10                	jmp    5445 <lagrange_interpolate+0x1f8>
    5435:	90                   	nop
    5436:	eb 0d                	jmp    5445 <lagrange_interpolate+0x1f8>
    5438:	90                   	nop
    5439:	eb 0a                	jmp    5445 <lagrange_interpolate+0x1f8>
    543b:	90                   	nop
    543c:	eb 07                	jmp    5445 <lagrange_interpolate+0x1f8>
    543e:	90                   	nop
    543f:	eb 04                	jmp    5445 <lagrange_interpolate+0x1f8>
    5441:	90                   	nop
    5442:	eb 01                	jmp    5445 <lagrange_interpolate+0x1f8>
    5444:	90                   	nop
    5445:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
    5449:	48 89 c7             	mov    rdi,rax
    544c:	e8 7f c3 ff ff       	call   17d0 <BN_CTX_end@plt>
    5451:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
    5454:	c9                   	leave  
    5455:	c3                   	ret    

0000000000005456 <verifiable_secret_sharing_reconstruct>:
    5456:	55                   	push   rbp
    5457:	48 89 e5             	mov    rbp,rsp
    545a:	48 83 ec 50          	sub    rsp,0x50
    545e:	48 89 7d c8          	mov    QWORD PTR [rbp-0x38],rdi
    5462:	89 f0                	mov    eax,esi
    5464:	48 89 55 b8          	mov    QWORD PTR [rbp-0x48],rdx
    5468:	89 4d c0             	mov    DWORD PTR [rbp-0x40],ecx
    546b:	4c 89 45 b0          	mov    QWORD PTR [rbp-0x50],r8
    546f:	88 45 c4             	mov    BYTE PTR [rbp-0x3c],al
    5472:	48 c7 45 d8 00 00 00 	mov    QWORD PTR [rbp-0x28],0x0
    5479:	00 
    547a:	48 c7 45 e0 00 00 00 	mov    QWORD PTR [rbp-0x20],0x0
    5481:	00 
    5482:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
    5489:	00 
    548a:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
    5491:	00 
    5492:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
    5499:	00 
    549a:	c7 45 d4 f8 ff ff ff 	mov    DWORD PTR [rbp-0x2c],0xfffffff8
    54a1:	48 83 7d c8 00       	cmp    QWORD PTR [rbp-0x38],0x0
    54a6:	74 13                	je     54bb <verifiable_secret_sharing_reconstruct+0x65>
    54a8:	80 7d c4 00          	cmp    BYTE PTR [rbp-0x3c],0x0
    54ac:	74 0d                	je     54bb <verifiable_secret_sharing_reconstruct+0x65>
    54ae:	48 83 7d b8 00       	cmp    QWORD PTR [rbp-0x48],0x0
    54b3:	75 10                	jne    54c5 <verifiable_secret_sharing_reconstruct+0x6f>
    54b5:	83 7d c0 00          	cmp    DWORD PTR [rbp-0x40],0x0
    54b9:	74 0a                	je     54c5 <verifiable_secret_sharing_reconstruct+0x6f>
    54bb:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    54c0:	e9 e2 02 00 00       	jmp    57a7 <verifiable_secret_sharing_reconstruct+0x351>
    54c5:	c6 45 d1 00          	mov    BYTE PTR [rbp-0x2f],0x0
    54c9:	e9 9b 00 00 00       	jmp    5569 <verifiable_secret_sharing_reconstruct+0x113>
    54ce:	0f b6 55 d1          	movzx  edx,BYTE PTR [rbp-0x2f]
    54d2:	48 89 d0             	mov    rax,rdx
    54d5:	48 c1 e0 02          	shl    rax,0x2
    54d9:	48 01 d0             	add    rax,rdx
    54dc:	48 c1 e0 03          	shl    rax,0x3
    54e0:	48 89 c2             	mov    rdx,rax
    54e3:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    54e7:	48 01 d0             	add    rax,rdx
    54ea:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
    54ee:	48 85 c0             	test   rax,rax
    54f1:	75 0a                	jne    54fd <verifiable_secret_sharing_reconstruct+0xa7>
    54f3:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    54f8:	e9 aa 02 00 00       	jmp    57a7 <verifiable_secret_sharing_reconstruct+0x351>
    54fd:	0f b6 45 d1          	movzx  eax,BYTE PTR [rbp-0x2f]
    5501:	83 c0 01             	add    eax,0x1
    5504:	88 45 d2             	mov    BYTE PTR [rbp-0x2e],al
    5507:	eb 53                	jmp    555c <verifiable_secret_sharing_reconstruct+0x106>
    5509:	0f b6 55 d1          	movzx  edx,BYTE PTR [rbp-0x2f]
    550d:	48 89 d0             	mov    rax,rdx
    5510:	48 c1 e0 02          	shl    rax,0x2
    5514:	48 01 d0             	add    rax,rdx
    5517:	48 c1 e0 03          	shl    rax,0x3
    551b:	48 89 c2             	mov    rdx,rax
    551e:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    5522:	48 01 d0             	add    rax,rdx
    5525:	48 8b 48 20          	mov    rcx,QWORD PTR [rax+0x20]
    5529:	0f b6 55 d2          	movzx  edx,BYTE PTR [rbp-0x2e]
    552d:	48 89 d0             	mov    rax,rdx
    5530:	48 c1 e0 02          	shl    rax,0x2
    5534:	48 01 d0             	add    rax,rdx
    5537:	48 c1 e0 03          	shl    rax,0x3
    553b:	48 89 c2             	mov    rdx,rax
    553e:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    5542:	48 01 d0             	add    rax,rdx
    5545:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
    5549:	48 39 c1             	cmp    rcx,rax
    554c:	75 0a                	jne    5558 <verifiable_secret_sharing_reconstruct+0x102>
    554e:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    5553:	e9 4f 02 00 00       	jmp    57a7 <verifiable_secret_sharing_reconstruct+0x351>
    5558:	80 45 d2 01          	add    BYTE PTR [rbp-0x2e],0x1
    555c:	0f b6 45 d2          	movzx  eax,BYTE PTR [rbp-0x2e]
    5560:	3a 45 c4             	cmp    al,BYTE PTR [rbp-0x3c]
    5563:	72 a4                	jb     5509 <verifiable_secret_sharing_reconstruct+0xb3>
    5565:	80 45 d1 01          	add    BYTE PTR [rbp-0x2f],0x1
    5569:	0f b6 45 d1          	movzx  eax,BYTE PTR [rbp-0x2f]
    556d:	3a 45 c4             	cmp    al,BYTE PTR [rbp-0x3c]
    5570:	0f 82 58 ff ff ff    	jb     54ce <verifiable_secret_sharing_reconstruct+0x78>
    5576:	e8 55 c1 ff ff       	call   16d0 <BN_CTX_new@plt>
    557b:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
    557f:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
    5584:	75 08                	jne    558e <verifiable_secret_sharing_reconstruct+0x138>
    5586:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
    5589:	e9 19 02 00 00       	jmp    57a7 <verifiable_secret_sharing_reconstruct+0x351>
    558e:	ba 00 00 00 00       	mov    edx,0x0
    5593:	be 20 00 00 00       	mov    esi,0x20
    5598:	48 8d 3d 81 36 00 00 	lea    rdi,[rip+0x3681]        # 8c20 <SECP256K1_FIELD>
    559f:	e8 dc bf ff ff       	call   1580 <BN_bin2bn@plt>
    55a4:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    55a8:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    55ad:	0f 84 b4 01 00 00    	je     5767 <verifiable_secret_sharing_reconstruct+0x311>
    55b3:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    55b7:	48 89 c7             	mov    rdi,rax
    55ba:	e8 41 c2 ff ff       	call   1800 <BN_CTX_start@plt>
    55bf:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    55c3:	48 89 c7             	mov    rdi,rax
    55c6:	e8 a5 c1 ff ff       	call   1770 <BN_CTX_get@plt>
    55cb:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
    55cf:	48 83 7d e0 00       	cmp    QWORD PTR [rbp-0x20],0x0
    55d4:	0f 84 90 01 00 00    	je     576a <verifiable_secret_sharing_reconstruct+0x314>
    55da:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    55de:	48 89 c7             	mov    rdi,rax
    55e1:	e8 8a c1 ff ff       	call   1770 <BN_CTX_get@plt>
    55e6:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
    55ea:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
    55ef:	0f 84 78 01 00 00    	je     576d <verifiable_secret_sharing_reconstruct+0x317>
    55f5:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    55f9:	48 89 c7             	mov    rdi,rax
    55fc:	e8 6f c1 ff ff       	call   1770 <BN_CTX_get@plt>
    5601:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
    5605:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
    560a:	0f 84 60 01 00 00    	je     5770 <verifiable_secret_sharing_reconstruct+0x31a>
    5610:	c6 45 d3 00          	mov    BYTE PTR [rbp-0x2d],0x0
    5614:	e9 b5 00 00 00       	jmp    56ce <verifiable_secret_sharing_reconstruct+0x278>
    5619:	0f b6 55 d3          	movzx  edx,BYTE PTR [rbp-0x2d]
    561d:	48 89 d0             	mov    rax,rdx
    5620:	48 c1 e0 02          	shl    rax,0x2
    5624:	48 01 d0             	add    rax,rdx
    5627:	48 c1 e0 03          	shl    rax,0x3
    562b:	48 89 c2             	mov    rdx,rax
    562e:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    5632:	48 01 d0             	add    rax,rdx
    5635:	48 89 c1             	mov    rcx,rax
    5638:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    563c:	48 89 c2             	mov    rdx,rax
    563f:	be 20 00 00 00       	mov    esi,0x20
    5644:	48 89 cf             	mov    rdi,rcx
    5647:	e8 34 bf ff ff       	call   1580 <BN_bin2bn@plt>
    564c:	48 85 c0             	test   rax,rax
    564f:	0f 84 1e 01 00 00    	je     5773 <verifiable_secret_sharing_reconstruct+0x31d>
    5655:	0f b6 55 d3          	movzx  edx,BYTE PTR [rbp-0x2d]
    5659:	0f b6 75 c4          	movzx  esi,BYTE PTR [rbp-0x3c]
    565d:	4c 8b 45 d8          	mov    r8,QWORD PTR [rbp-0x28]
    5661:	48 8b 7d f8          	mov    rdi,QWORD PTR [rbp-0x8]
    5665:	48 8b 4d e8          	mov    rcx,QWORD PTR [rbp-0x18]
    5669:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    566d:	4d 89 c1             	mov    r9,r8
    5670:	49 89 f8             	mov    r8,rdi
    5673:	48 89 c7             	mov    rdi,rax
    5676:	e8 d2 fb ff ff       	call   524d <lagrange_interpolate>
    567b:	85 c0                	test   eax,eax
    567d:	0f 84 f3 00 00 00    	je     5776 <verifiable_secret_sharing_reconstruct+0x320>
    5683:	48 8b 7d d8          	mov    rdi,QWORD PTR [rbp-0x28]
    5687:	48 8b 4d f8          	mov    rcx,QWORD PTR [rbp-0x8]
    568b:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
    568f:	48 8b 75 f0          	mov    rsi,QWORD PTR [rbp-0x10]
    5693:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    5697:	49 89 f8             	mov    r8,rdi
    569a:	48 89 c7             	mov    rdi,rax
    569d:	e8 1e be ff ff       	call   14c0 <BN_mod_mul@plt>
    56a2:	85 c0                	test   eax,eax
    56a4:	0f 84 cf 00 00 00    	je     5779 <verifiable_secret_sharing_reconstruct+0x323>
    56aa:	48 8b 4d f8          	mov    rcx,QWORD PTR [rbp-0x8]
    56ae:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
    56b2:	48 8b 75 e0          	mov    rsi,QWORD PTR [rbp-0x20]
    56b6:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
    56ba:	48 89 c7             	mov    rdi,rax
    56bd:	e8 6e c0 ff ff       	call   1730 <BN_mod_add_quick@plt>
    56c2:	85 c0                	test   eax,eax
    56c4:	0f 84 b2 00 00 00    	je     577c <verifiable_secret_sharing_reconstruct+0x326>
    56ca:	80 45 d3 01          	add    BYTE PTR [rbp-0x2d],0x1
    56ce:	0f b6 45 d3          	movzx  eax,BYTE PTR [rbp-0x2d]
    56d2:	3a 45 c4             	cmp    al,BYTE PTR [rbp-0x3c]
    56d5:	0f 82 3e ff ff ff    	jb     5619 <verifiable_secret_sharing_reconstruct+0x1c3>
    56db:	48 83 7d b0 00       	cmp    QWORD PTR [rbp-0x50],0x0
    56e0:	74 22                	je     5704 <verifiable_secret_sharing_reconstruct+0x2ae>
    56e2:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
    56e6:	48 89 c7             	mov    rdi,rax
    56e9:	e8 d2 be ff ff       	call   15c0 <BN_num_bits@plt>
    56ee:	83 c0 07             	add    eax,0x7
    56f1:	8d 50 07             	lea    edx,[rax+0x7]
    56f4:	85 c0                	test   eax,eax
    56f6:	0f 48 c2             	cmovs  eax,edx
    56f9:	c1 f8 03             	sar    eax,0x3
    56fc:	89 c2                	mov    edx,eax
    56fe:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
    5702:	89 10                	mov    DWORD PTR [rax],edx
    5704:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
    5708:	48 89 c7             	mov    rdi,rax
    570b:	e8 b0 be ff ff       	call   15c0 <BN_num_bits@plt>
    5710:	83 c0 07             	add    eax,0x7
    5713:	8d 50 07             	lea    edx,[rax+0x7]
    5716:	85 c0                	test   eax,eax
    5718:	0f 48 c2             	cmovs  eax,edx
    571b:	c1 f8 03             	sar    eax,0x3
    571e:	39 45 c0             	cmp    DWORD PTR [rbp-0x40],eax
    5721:	72 07                	jb     572a <verifiable_secret_sharing_reconstruct+0x2d4>
    5723:	b8 00 00 00 00       	mov    eax,0x0
    5728:	eb 05                	jmp    572f <verifiable_secret_sharing_reconstruct+0x2d9>
    572a:	b8 f9 ff ff ff       	mov    eax,0xfffffff9
    572f:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
    5732:	83 7d d4 00          	cmp    DWORD PTR [rbp-0x2c],0x0
    5736:	75 47                	jne    577f <verifiable_secret_sharing_reconstruct+0x329>
    5738:	48 83 7d b8 00       	cmp    QWORD PTR [rbp-0x48],0x0
    573d:	74 40                	je     577f <verifiable_secret_sharing_reconstruct+0x329>
    573f:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
    5743:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
    5747:	48 89 d6             	mov    rsi,rdx
    574a:	48 89 c7             	mov    rdi,rax
    574d:	e8 2e c0 ff ff       	call   1780 <BN_bn2bin@plt>
    5752:	85 c0                	test   eax,eax
    5754:	7e 07                	jle    575d <verifiable_secret_sharing_reconstruct+0x307>
    5756:	b8 00 00 00 00       	mov    eax,0x0
    575b:	eb 05                	jmp    5762 <verifiable_secret_sharing_reconstruct+0x30c>
    575d:	b8 ff ff ff ff       	mov    eax,0xffffffff
    5762:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
    5765:	eb 19                	jmp    5780 <verifiable_secret_sharing_reconstruct+0x32a>
    5767:	90                   	nop
    5768:	eb 16                	jmp    5780 <verifiable_secret_sharing_reconstruct+0x32a>
    576a:	90                   	nop
    576b:	eb 13                	jmp    5780 <verifiable_secret_sharing_reconstruct+0x32a>
    576d:	90                   	nop
    576e:	eb 10                	jmp    5780 <verifiable_secret_sharing_reconstruct+0x32a>
    5770:	90                   	nop
    5771:	eb 0d                	jmp    5780 <verifiable_secret_sharing_reconstruct+0x32a>
    5773:	90                   	nop
    5774:	eb 0a                	jmp    5780 <verifiable_secret_sharing_reconstruct+0x32a>
    5776:	90                   	nop
    5777:	eb 07                	jmp    5780 <verifiable_secret_sharing_reconstruct+0x32a>
    5779:	90                   	nop
    577a:	eb 04                	jmp    5780 <verifiable_secret_sharing_reconstruct+0x32a>
    577c:	90                   	nop
    577d:	eb 01                	jmp    5780 <verifiable_secret_sharing_reconstruct+0x32a>
    577f:	90                   	nop
    5780:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    5784:	48 89 c7             	mov    rdi,rax
    5787:	e8 94 c0 ff ff       	call   1820 <BN_free@plt>
    578c:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    5790:	48 89 c7             	mov    rdi,rax
    5793:	e8 38 c0 ff ff       	call   17d0 <BN_CTX_end@plt>
    5798:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    579c:	48 89 c7             	mov    rdi,rax
    579f:	e8 2c bd ff ff       	call   14d0 <BN_CTX_free@plt>
    57a4:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
    57a7:	c9                   	leave  
    57a8:	c3                   	ret    

00000000000057a9 <verifiable_secret_sharing_verify_share>:
    57a9:	55                   	push   rbp
    57aa:	48 89 e5             	mov    rbp,rsp
    57ad:	48 83 ec 60          	sub    rsp,0x60
    57b1:	48 89 7d b8          	mov    QWORD PTR [rbp-0x48],rdi
    57b5:	48 89 75 b0          	mov    QWORD PTR [rbp-0x50],rsi
    57b9:	89 d0                	mov    eax,edx
    57bb:	48 89 4d a0          	mov    QWORD PTR [rbp-0x60],rcx
    57bf:	88 45 ac             	mov    BYTE PTR [rbp-0x54],al
    57c2:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    57c9:	00 00 
    57cb:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    57cf:	31 c0                	xor    eax,eax
    57d1:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
    57d8:	00 
    57d9:	48 c7 45 d8 00 00 00 	mov    QWORD PTR [rbp-0x28],0x0
    57e0:	00 
    57e1:	48 c7 45 e0 00 00 00 	mov    QWORD PTR [rbp-0x20],0x0
    57e8:	00 
    57e9:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
    57f0:	00 
    57f1:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
    57f8:	00 
    57f9:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
    5800:	00 
    5801:	c6 45 c2 00          	mov    BYTE PTR [rbp-0x3e],0x0
    5805:	c7 45 c4 f8 ff ff ff 	mov    DWORD PTR [rbp-0x3c],0xfffffff8
    580c:	48 83 7d b0 00       	cmp    QWORD PTR [rbp-0x50],0x0
    5811:	74 0d                	je     5820 <verifiable_secret_sharing_verify_share+0x77>
    5813:	80 7d ac 00          	cmp    BYTE PTR [rbp-0x54],0x0
    5817:	74 07                	je     5820 <verifiable_secret_sharing_verify_share+0x77>
    5819:	48 83 7d a0 00       	cmp    QWORD PTR [rbp-0x60],0x0
    581e:	75 0a                	jne    582a <verifiable_secret_sharing_verify_share+0x81>
    5820:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    5825:	e9 27 02 00 00       	jmp    5a51 <verifiable_secret_sharing_verify_share+0x2a8>
    582a:	e8 a1 be ff ff       	call   16d0 <BN_CTX_new@plt>
    582f:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
    5833:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
    5838:	75 0a                	jne    5844 <verifiable_secret_sharing_verify_share+0x9b>
    583a:	b8 f8 ff ff ff       	mov    eax,0xfffffff8
    583f:	e9 0d 02 00 00       	jmp    5a51 <verifiable_secret_sharing_verify_share+0x2a8>
    5844:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    5848:	48 89 c7             	mov    rdi,rax
    584b:	e8 b0 bf ff ff       	call   1800 <BN_CTX_start@plt>
    5850:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    5854:	48 89 c7             	mov    rdi,rax
    5857:	e8 14 bf ff ff       	call   1770 <BN_CTX_get@plt>
    585c:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
    5860:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
    5865:	0f 84 a5 01 00 00    	je     5a10 <verifiable_secret_sharing_verify_share+0x267>
    586b:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
    586f:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    5873:	48 89 d6             	mov    rsi,rdx
    5876:	48 89 c7             	mov    rdi,rax
    5879:	e8 f2 bc ff ff       	call   1570 <BN_set_word@plt>
    587e:	85 c0                	test   eax,eax
    5880:	0f 84 8a 01 00 00    	je     5a10 <verifiable_secret_sharing_verify_share+0x267>
    5886:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    588a:	48 89 c7             	mov    rdi,rax
    588d:	e8 de be ff ff       	call   1770 <BN_CTX_get@plt>
    5892:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
    5896:	48 83 7d e0 00       	cmp    QWORD PTR [rbp-0x20],0x0
    589b:	0f 84 6f 01 00 00    	je     5a10 <verifiable_secret_sharing_verify_share+0x267>
    58a1:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
    58a5:	be 01 00 00 00       	mov    esi,0x1
    58aa:	48 89 c7             	mov    rdi,rax
    58ad:	e8 be bc ff ff       	call   1570 <BN_set_word@plt>
    58b2:	85 c0                	test   eax,eax
    58b4:	0f 84 56 01 00 00    	je     5a10 <verifiable_secret_sharing_verify_share+0x267>
    58ba:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    58be:	48 89 c7             	mov    rdi,rax
    58c1:	e8 aa be ff ff       	call   1770 <BN_CTX_get@plt>
    58c6:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
    58ca:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
    58cf:	0f 84 3b 01 00 00    	je     5a10 <verifiable_secret_sharing_verify_share+0x267>
    58d5:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    58d9:	48 89 c2             	mov    rdx,rax
    58dc:	be 20 00 00 00       	mov    esi,0x20
    58e1:	48 8d 3d 38 33 00 00 	lea    rdi,[rip+0x3338]        # 8c20 <SECP256K1_FIELD>
    58e8:	e8 93 bc ff ff       	call   1580 <BN_bin2bn@plt>
    58ed:	48 85 c0             	test   rax,rax
    58f0:	0f 84 1a 01 00 00    	je     5a10 <verifiable_secret_sharing_verify_share+0x267>
    58f6:	0f b6 45 ac          	movzx  eax,BYTE PTR [rbp-0x54]
    58fa:	be 20 00 00 00       	mov    esi,0x20
    58ff:	48 89 c7             	mov    rdi,rax
    5902:	e8 19 be ff ff       	call   1720 <calloc@plt>
    5907:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
    590b:	48 83 7d c8 00       	cmp    QWORD PTR [rbp-0x38],0x0
    5910:	0f 84 fd 00 00 00    	je     5a13 <verifiable_secret_sharing_verify_share+0x26a>
    5916:	48 8b 4d c8          	mov    rcx,QWORD PTR [rbp-0x38]
    591a:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
    591e:	ba 20 00 00 00       	mov    edx,0x20
    5923:	48 89 ce             	mov    rsi,rcx
    5926:	48 89 c7             	mov    rdi,rax
    5929:	e8 82 bb ff ff       	call   14b0 <BN_bn2binpad@plt>
    592e:	85 c0                	test   eax,eax
    5930:	79 0c                	jns    593e <verifiable_secret_sharing_verify_share+0x195>
    5932:	c7 45 c4 ff ff ff ff 	mov    DWORD PTR [rbp-0x3c],0xffffffff
    5939:	e9 d9 00 00 00       	jmp    5a17 <verifiable_secret_sharing_verify_share+0x26e>
    593e:	c6 45 c3 00          	mov    BYTE PTR [rbp-0x3d],0x0
    5942:	eb 63                	jmp    59a7 <verifiable_secret_sharing_verify_share+0x1fe>
    5944:	48 8b 7d f0          	mov    rdi,QWORD PTR [rbp-0x10]
    5948:	48 8b 4d e8          	mov    rcx,QWORD PTR [rbp-0x18]
    594c:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
    5950:	48 8b 75 e0          	mov    rsi,QWORD PTR [rbp-0x20]
    5954:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
    5958:	49 89 f8             	mov    r8,rdi
    595b:	48 89 c7             	mov    rdi,rax
    595e:	e8 5d bb ff ff       	call   14c0 <BN_mod_mul@plt>
    5963:	85 c0                	test   eax,eax
    5965:	0f 84 ab 00 00 00    	je     5a16 <verifiable_secret_sharing_verify_share+0x26d>
    596b:	0f b6 45 c3          	movzx  eax,BYTE PTR [rbp-0x3d]
    596f:	48 83 c0 01          	add    rax,0x1
    5973:	48 c1 e0 05          	shl    rax,0x5
    5977:	48 89 c2             	mov    rdx,rax
    597a:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    597e:	48 8d 0c 02          	lea    rcx,[rdx+rax*1]
    5982:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
    5986:	ba 20 00 00 00       	mov    edx,0x20
    598b:	48 89 ce             	mov    rsi,rcx
    598e:	48 89 c7             	mov    rdi,rax
    5991:	e8 1a bb ff ff       	call   14b0 <BN_bn2binpad@plt>
    5996:	85 c0                	test   eax,eax
    5998:	79 09                	jns    59a3 <verifiable_secret_sharing_verify_share+0x1fa>
    599a:	c7 45 c4 ff ff ff ff 	mov    DWORD PTR [rbp-0x3c],0xffffffff
    59a1:	eb 74                	jmp    5a17 <verifiable_secret_sharing_verify_share+0x26e>
    59a3:	80 45 c3 01          	add    BYTE PTR [rbp-0x3d],0x1
    59a7:	0f b6 45 c3          	movzx  eax,BYTE PTR [rbp-0x3d]
    59ab:	0f b6 55 ac          	movzx  edx,BYTE PTR [rbp-0x54]
    59af:	83 ea 01             	sub    edx,0x1
    59b2:	39 d0                	cmp    eax,edx
    59b4:	7c 8e                	jl     5944 <verifiable_secret_sharing_verify_share+0x19b>
    59b6:	b8 00 00 00 00       	mov    eax,0x0
    59bb:	e8 7f 01 00 00       	call   5b3f <secp256k1_algebra_ctx_new>
    59c0:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
    59c4:	0f b6 7d ac          	movzx  edi,BYTE PTR [rbp-0x54]
    59c8:	4c 8d 45 c2          	lea    r8,[rbp-0x3e]
    59cc:	48 8b 4d c8          	mov    rcx,QWORD PTR [rbp-0x38]
    59d0:	48 8b 55 a0          	mov    rdx,QWORD PTR [rbp-0x60]
    59d4:	48 8b 75 b0          	mov    rsi,QWORD PTR [rbp-0x50]
    59d8:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
    59dc:	4d 89 c1             	mov    r9,r8
    59df:	41 89 f8             	mov    r8d,edi
    59e2:	48 89 c7             	mov    rdi,rax
    59e5:	e8 04 07 00 00       	call   60ee <secp256k1_algebra_verify_linear_combination>
    59ea:	85 c0                	test   eax,eax
    59ec:	74 09                	je     59f7 <verifiable_secret_sharing_verify_share+0x24e>
    59ee:	c7 45 c4 ff ff ff ff 	mov    DWORD PTR [rbp-0x3c],0xffffffff
    59f5:	eb 20                	jmp    5a17 <verifiable_secret_sharing_verify_share+0x26e>
    59f7:	0f b6 45 c2          	movzx  eax,BYTE PTR [rbp-0x3e]
    59fb:	84 c0                	test   al,al
    59fd:	74 07                	je     5a06 <verifiable_secret_sharing_verify_share+0x25d>
    59ff:	b8 00 00 00 00       	mov    eax,0x0
    5a04:	eb 05                	jmp    5a0b <verifiable_secret_sharing_verify_share+0x262>
    5a06:	b8 fb ff ff ff       	mov    eax,0xfffffffb
    5a0b:	89 45 c4             	mov    DWORD PTR [rbp-0x3c],eax
    5a0e:	eb 07                	jmp    5a17 <verifiable_secret_sharing_verify_share+0x26e>
    5a10:	90                   	nop
    5a11:	eb 04                	jmp    5a17 <verifiable_secret_sharing_verify_share+0x26e>
    5a13:	90                   	nop
    5a14:	eb 01                	jmp    5a17 <verifiable_secret_sharing_verify_share+0x26e>
    5a16:	90                   	nop
    5a17:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
    5a1c:	74 18                	je     5a36 <verifiable_secret_sharing_verify_share+0x28d>
    5a1e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    5a22:	48 89 c7             	mov    rdi,rax
    5a25:	e8 a6 bd ff ff       	call   17d0 <BN_CTX_end@plt>
    5a2a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    5a2e:	48 89 c7             	mov    rdi,rax
    5a31:	e8 9a ba ff ff       	call   14d0 <BN_CTX_free@plt>
    5a36:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
    5a3a:	48 89 c7             	mov    rdi,rax
    5a3d:	e8 53 01 00 00       	call   5b95 <secp256k1_algebra_ctx_free>
    5a42:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    5a46:	48 89 c7             	mov    rdi,rax
    5a49:	e8 d2 bb ff ff       	call   1620 <free@plt>
    5a4e:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
    5a51:	48 8b 4d f8          	mov    rcx,QWORD PTR [rbp-0x8]
    5a55:	64 48 33 0c 25 28 00 	xor    rcx,QWORD PTR fs:0x28
    5a5c:	00 00 
    5a5e:	74 05                	je     5a65 <verifiable_secret_sharing_verify_share+0x2bc>
    5a60:	e8 8b bc ff ff       	call   16f0 <__stack_chk_fail@plt>
    5a65:	c9                   	leave  
    5a66:	c3                   	ret    

0000000000005a67 <verifiable_secret_sharing_verify_commitment>:
    5a67:	55                   	push   rbp
    5a68:	48 89 e5             	mov    rbp,rsp
    5a6b:	48 83 ec 20          	sub    rsp,0x20
    5a6f:	48 89 7d f8          	mov    QWORD PTR [rbp-0x8],rdi
    5a73:	89 f0                	mov    eax,esi
    5a75:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
    5a79:	88 45 f4             	mov    BYTE PTR [rbp-0xc],al
    5a7c:	0f b6 55 f4          	movzx  edx,BYTE PTR [rbp-0xc]
    5a80:	89 d0                	mov    eax,edx
    5a82:	c1 e0 05             	shl    eax,0x5
    5a85:	8d 0c 10             	lea    ecx,[rax+rdx*1]
    5a88:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
    5a8c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    5a90:	89 ce                	mov    esi,ecx
    5a92:	48 89 c7             	mov    rdi,rax
    5a95:	e8 df 1b 00 00       	call   7679 <commitments_verify_commitment>
    5a9a:	89 c7                	mov    edi,eax
    5a9c:	e8 c8 e5 ff ff       	call   4069 <from_commitments_status>
    5aa1:	c9                   	leave  
    5aa2:	c3                   	ret    

0000000000005aa3 <verifiable_secret_sharing_free_shares>:
    5aa3:	55                   	push   rbp
    5aa4:	48 89 e5             	mov    rbp,rsp
    5aa7:	48 83 ec 10          	sub    rsp,0x10
    5aab:	48 89 7d f8          	mov    QWORD PTR [rbp-0x8],rdi
    5aaf:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    5ab4:	0f 84 82 00 00 00    	je     5b3c <verifiable_secret_sharing_free_shares+0x99>
    5aba:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    5abe:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
    5ac2:	48 89 c7             	mov    rdi,rax
    5ac5:	e8 56 bb ff ff       	call   1620 <free@plt>
    5aca:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    5ace:	0f b6 40 28          	movzx  eax,BYTE PTR [rax+0x28]
    5ad2:	0f b6 c0             	movzx  eax,al
    5ad5:	48 c1 e0 05          	shl    rax,0x5
    5ad9:	48 89 c2             	mov    rdx,rax
    5adc:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    5ae0:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
    5ae4:	be 00 00 00 00       	mov    esi,0x0
    5ae9:	48 89 c7             	mov    rdi,rax
    5aec:	e8 9f b9 ff ff       	call   1490 <memset@plt>
    5af1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    5af5:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
    5af9:	48 89 c7             	mov    rdi,rax
    5afc:	e8 1f bb ff ff       	call   1620 <free@plt>
    5b01:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    5b05:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
    5b09:	48 89 c7             	mov    rdi,rax
    5b0c:	e8 0f bb ff ff       	call   1620 <free@plt>
    5b11:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    5b15:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
    5b19:	48 89 c7             	mov    rdi,rax
    5b1c:	e8 ff ba ff ff       	call   1620 <free@plt>
    5b21:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    5b25:	48 8b 00             	mov    rax,QWORD PTR [rax]
    5b28:	48 89 c7             	mov    rdi,rax
    5b2b:	e8 65 00 00 00       	call   5b95 <secp256k1_algebra_ctx_free>
    5b30:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    5b34:	48 89 c7             	mov    rdi,rax
    5b37:	e8 e4 ba ff ff       	call   1620 <free@plt>
    5b3c:	90                   	nop
    5b3d:	c9                   	leave  
    5b3e:	c3                   	ret    

0000000000005b3f <secp256k1_algebra_ctx_new>:
    5b3f:	55                   	push   rbp
    5b40:	48 89 e5             	mov    rbp,rsp
    5b43:	48 83 ec 10          	sub    rsp,0x10
    5b47:	bf 08 00 00 00       	mov    edi,0x8
    5b4c:	e8 0f ba ff ff       	call   1560 <malloc@plt>
    5b51:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    5b55:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    5b5a:	74 33                	je     5b8f <secp256k1_algebra_ctx_new+0x50>
    5b5c:	bf ca 02 00 00       	mov    edi,0x2ca
    5b61:	e8 ca b9 ff ff       	call   1530 <EC_GROUP_new_by_curve_name@plt>
    5b66:	48 89 c2             	mov    rdx,rax
    5b69:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    5b6d:	48 89 10             	mov    QWORD PTR [rax],rdx
    5b70:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    5b74:	48 8b 00             	mov    rax,QWORD PTR [rax]
    5b77:	48 85 c0             	test   rax,rax
    5b7a:	75 13                	jne    5b8f <secp256k1_algebra_ctx_new+0x50>
    5b7c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    5b80:	48 89 c7             	mov    rdi,rax
    5b83:	e8 98 ba ff ff       	call   1620 <free@plt>
    5b88:	b8 00 00 00 00       	mov    eax,0x0
    5b8d:	eb 04                	jmp    5b93 <secp256k1_algebra_ctx_new+0x54>
    5b8f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    5b93:	c9                   	leave  
    5b94:	c3                   	ret    

0000000000005b95 <secp256k1_algebra_ctx_free>:
    5b95:	55                   	push   rbp
    5b96:	48 89 e5             	mov    rbp,rsp
    5b99:	48 83 ec 10          	sub    rsp,0x10
    5b9d:	48 89 7d f8          	mov    QWORD PTR [rbp-0x8],rdi
    5ba1:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    5ba6:	74 1b                	je     5bc3 <secp256k1_algebra_ctx_free+0x2e>
    5ba8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    5bac:	48 8b 00             	mov    rax,QWORD PTR [rax]
    5baf:	48 89 c7             	mov    rdi,rax
    5bb2:	e8 d9 b9 ff ff       	call   1590 <EC_GROUP_free@plt>
    5bb7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    5bbb:	48 89 c7             	mov    rdi,rax
    5bbe:	e8 5d ba ff ff       	call   1620 <free@plt>
    5bc3:	90                   	nop
    5bc4:	c9                   	leave  
    5bc5:	c3                   	ret    

0000000000005bc6 <from_openssl_error>:
    5bc6:	55                   	push   rbp
    5bc7:	48 89 e5             	mov    rbp,rsp
    5bca:	48 89 7d f8          	mov    QWORD PTR [rbp-0x8],rdi
    5bce:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    5bd2:	48 c1 f8 18          	sar    rax,0x18
    5bd6:	0f b6 c0             	movzx  eax,al
    5bd9:	83 f8 10             	cmp    eax,0x10
    5bdc:	75 23                	jne    5c01 <from_openssl_error+0x3b>
    5bde:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    5be2:	25 ff 0f 00 00       	and    eax,0xfff
    5be7:	83 f8 66             	cmp    eax,0x66
    5bea:	74 0e                	je     5bfa <from_openssl_error+0x34>
    5bec:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    5bf0:	25 ff 0f 00 00       	and    eax,0xfff
    5bf5:	83 f8 6e             	cmp    eax,0x6e
    5bf8:	75 07                	jne    5c01 <from_openssl_error+0x3b>
    5bfa:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    5bff:	eb 1a                	jmp    5c1b <from_openssl_error+0x55>
    5c01:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    5c05:	25 ff 0f 00 00       	and    eax,0xfff
    5c0a:	83 f8 41             	cmp    eax,0x41
    5c0d:	75 07                	jne    5c16 <from_openssl_error+0x50>
    5c0f:	b8 fc ff ff ff       	mov    eax,0xfffffffc
    5c14:	eb 05                	jmp    5c1b <from_openssl_error+0x55>
    5c16:	b8 ff ff ff ff       	mov    eax,0xffffffff
    5c1b:	5d                   	pop    rbp
    5c1c:	c3                   	ret    

0000000000005c1d <secp256k1_algebra_generate_proof_for_data>:
    5c1d:	55                   	push   rbp
    5c1e:	48 89 e5             	mov    rbp,rsp
    5c21:	48 83 ec 40          	sub    rsp,0x40
    5c25:	48 89 7d d8          	mov    QWORD PTR [rbp-0x28],rdi
    5c29:	48 89 75 d0          	mov    QWORD PTR [rbp-0x30],rsi
    5c2d:	89 55 cc             	mov    DWORD PTR [rbp-0x34],edx
    5c30:	48 89 4d c0          	mov    QWORD PTR [rbp-0x40],rcx
    5c34:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
    5c3b:	00 
    5c3c:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
    5c43:	00 
    5c44:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
    5c4b:	00 
    5c4c:	c7 45 e4 ff ff ff ff 	mov    DWORD PTR [rbp-0x1c],0xffffffff
    5c53:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
    5c58:	74 14                	je     5c6e <secp256k1_algebra_generate_proof_for_data+0x51>
    5c5a:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
    5c5f:	74 0d                	je     5c6e <secp256k1_algebra_generate_proof_for_data+0x51>
    5c61:	48 83 7d c0 00       	cmp    QWORD PTR [rbp-0x40],0x0
    5c66:	74 06                	je     5c6e <secp256k1_algebra_generate_proof_for_data+0x51>
    5c68:	83 7d cc 00          	cmp    DWORD PTR [rbp-0x34],0x0
    5c6c:	75 0a                	jne    5c78 <secp256k1_algebra_generate_proof_for_data+0x5b>
    5c6e:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    5c73:	e9 41 01 00 00       	jmp    5db9 <secp256k1_algebra_generate_proof_for_data+0x19c>
    5c78:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
    5c7c:	ba 21 00 00 00       	mov    edx,0x21
    5c81:	be 00 00 00 00       	mov    esi,0x0
    5c86:	48 89 c7             	mov    rdi,rax
    5c89:	e8 02 b8 ff ff       	call   1490 <memset@plt>
    5c8e:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    5c92:	48 8b 00             	mov    rax,QWORD PTR [rax]
    5c95:	48 89 c7             	mov    rdi,rax
    5c98:	e8 03 b9 ff ff       	call   15a0 <EC_POINT_new@plt>
    5c9d:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
    5ca1:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
    5ca6:	75 0a                	jne    5cb2 <secp256k1_algebra_generate_proof_for_data+0x95>
    5ca8:	b8 fc ff ff ff       	mov    eax,0xfffffffc
    5cad:	e9 07 01 00 00       	jmp    5db9 <secp256k1_algebra_generate_proof_for_data+0x19c>
    5cb2:	e8 19 ba ff ff       	call   16d0 <BN_CTX_new@plt>
    5cb7:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
    5cbb:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
    5cc0:	75 16                	jne    5cd8 <secp256k1_algebra_generate_proof_for_data+0xbb>
    5cc2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    5cc6:	48 89 c7             	mov    rdi,rax
    5cc9:	e8 82 ba ff ff       	call   1750 <EC_POINT_free@plt>
    5cce:	b8 fc ff ff ff       	mov    eax,0xfffffffc
    5cd3:	e9 e1 00 00 00       	jmp    5db9 <secp256k1_algebra_generate_proof_for_data+0x19c>
    5cd8:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    5cdc:	48 89 c7             	mov    rdi,rax
    5cdf:	e8 1c bb ff ff       	call   1800 <BN_CTX_start@plt>
    5ce4:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    5ce8:	48 89 c7             	mov    rdi,rax
    5ceb:	e8 80 ba ff ff       	call   1770 <BN_CTX_get@plt>
    5cf0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    5cf4:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    5cf9:	74 1a                	je     5d15 <secp256k1_algebra_generate_proof_for_data+0xf8>
    5cfb:	8b 4d cc             	mov    ecx,DWORD PTR [rbp-0x34]
    5cfe:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
    5d02:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
    5d06:	89 ce                	mov    esi,ecx
    5d08:	48 89 c7             	mov    rdi,rax
    5d0b:	e8 70 b8 ff ff       	call   1580 <BN_bin2bn@plt>
    5d10:	48 85 c0             	test   rax,rax
    5d13:	75 09                	jne    5d1e <secp256k1_algebra_generate_proof_for_data+0x101>
    5d15:	c7 45 e4 fc ff ff ff 	mov    DWORD PTR [rbp-0x1c],0xfffffffc
    5d1c:	eb 68                	jmp    5d86 <secp256k1_algebra_generate_proof_for_data+0x169>
    5d1e:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    5d22:	48 8b 00             	mov    rax,QWORD PTR [rax]
    5d25:	48 8b 4d e8          	mov    rcx,QWORD PTR [rbp-0x18]
    5d29:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
    5d2d:	48 8b 75 f0          	mov    rsi,QWORD PTR [rbp-0x10]
    5d31:	49 89 c9             	mov    r9,rcx
    5d34:	41 b8 00 00 00 00    	mov    r8d,0x0
    5d3a:	b9 00 00 00 00       	mov    ecx,0x0
    5d3f:	48 89 c7             	mov    rdi,rax
    5d42:	e8 99 b9 ff ff       	call   16e0 <EC_POINT_mul@plt>
    5d47:	85 c0                	test   eax,eax
    5d49:	74 3a                	je     5d85 <secp256k1_algebra_generate_proof_for_data+0x168>
    5d4b:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    5d4f:	48 8b 00             	mov    rax,QWORD PTR [rax]
    5d52:	48 8b 4d e8          	mov    rcx,QWORD PTR [rbp-0x18]
    5d56:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
    5d5a:	48 8b 75 f0          	mov    rsi,QWORD PTR [rbp-0x10]
    5d5e:	49 89 c9             	mov    r9,rcx
    5d61:	41 b8 21 00 00 00    	mov    r8d,0x21
    5d67:	48 89 d1             	mov    rcx,rdx
    5d6a:	ba 02 00 00 00       	mov    edx,0x2
    5d6f:	48 89 c7             	mov    rdi,rax
    5d72:	e8 b9 b8 ff ff       	call   1630 <EC_POINT_point2oct@plt>
    5d77:	48 85 c0             	test   rax,rax
    5d7a:	74 09                	je     5d85 <secp256k1_algebra_generate_proof_for_data+0x168>
    5d7c:	c7 45 e4 00 00 00 00 	mov    DWORD PTR [rbp-0x1c],0x0
    5d83:	eb 01                	jmp    5d86 <secp256k1_algebra_generate_proof_for_data+0x169>
    5d85:	90                   	nop
    5d86:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    5d8a:	48 89 c7             	mov    rdi,rax
    5d8d:	e8 de b8 ff ff       	call   1670 <BN_clear@plt>
    5d92:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    5d96:	48 89 c7             	mov    rdi,rax
    5d99:	e8 32 ba ff ff       	call   17d0 <BN_CTX_end@plt>
    5d9e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    5da2:	48 89 c7             	mov    rdi,rax
    5da5:	e8 26 b7 ff ff       	call   14d0 <BN_CTX_free@plt>
    5daa:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    5dae:	48 89 c7             	mov    rdi,rax
    5db1:	e8 9a b9 ff ff       	call   1750 <EC_POINT_free@plt>
    5db6:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
    5db9:	c9                   	leave  
    5dba:	c3                   	ret    

0000000000005dbb <secp256k1_algebra_verify>:
    5dbb:	55                   	push   rbp
    5dbc:	48 89 e5             	mov    rbp,rsp
    5dbf:	48 83 ec 70          	sub    rsp,0x70
    5dc3:	48 89 7d b8          	mov    QWORD PTR [rbp-0x48],rdi
    5dc7:	48 89 75 b0          	mov    QWORD PTR [rbp-0x50],rsi
    5dcb:	89 55 ac             	mov    DWORD PTR [rbp-0x54],edx
    5dce:	48 89 4d a0          	mov    QWORD PTR [rbp-0x60],rcx
    5dd2:	4c 89 45 98          	mov    QWORD PTR [rbp-0x68],r8
    5dd6:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    5ddd:	00 00 
    5ddf:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    5de3:	31 c0                	xor    eax,eax
    5de5:	48 83 7d 98 00       	cmp    QWORD PTR [rbp-0x68],0x0
    5dea:	74 07                	je     5df3 <secp256k1_algebra_verify+0x38>
    5dec:	48 83 7d a0 00       	cmp    QWORD PTR [rbp-0x60],0x0
    5df1:	75 07                	jne    5dfa <secp256k1_algebra_verify+0x3f>
    5df3:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    5df8:	eb 4f                	jmp    5e49 <secp256k1_algebra_verify+0x8e>
    5dfa:	48 8b 45 98          	mov    rax,QWORD PTR [rbp-0x68]
    5dfe:	c6 00 00             	mov    BYTE PTR [rax],0x0
    5e01:	48 8d 4d d0          	lea    rcx,[rbp-0x30]
    5e05:	8b 55 ac             	mov    edx,DWORD PTR [rbp-0x54]
    5e08:	48 8b 75 b0          	mov    rsi,QWORD PTR [rbp-0x50]
    5e0c:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
    5e10:	48 89 c7             	mov    rdi,rax
    5e13:	e8 05 fe ff ff       	call   5c1d <secp256k1_algebra_generate_proof_for_data>
    5e18:	89 45 cc             	mov    DWORD PTR [rbp-0x34],eax
    5e1b:	83 7d cc 00          	cmp    DWORD PTR [rbp-0x34],0x0
    5e1f:	75 25                	jne    5e46 <secp256k1_algebra_verify+0x8b>
    5e21:	48 8b 4d a0          	mov    rcx,QWORD PTR [rbp-0x60]
    5e25:	48 8d 45 d0          	lea    rax,[rbp-0x30]
    5e29:	ba 21 00 00 00       	mov    edx,0x21
    5e2e:	48 89 ce             	mov    rsi,rcx
    5e31:	48 89 c7             	mov    rdi,rax
    5e34:	e8 d7 b9 ff ff       	call   1810 <CRYPTO_memcmp@plt>
    5e39:	85 c0                	test   eax,eax
    5e3b:	0f 94 c0             	sete   al
    5e3e:	89 c2                	mov    edx,eax
    5e40:	48 8b 45 98          	mov    rax,QWORD PTR [rbp-0x68]
    5e44:	88 10                	mov    BYTE PTR [rax],dl
    5e46:	8b 45 cc             	mov    eax,DWORD PTR [rbp-0x34]
    5e49:	48 8b 7d f8          	mov    rdi,QWORD PTR [rbp-0x8]
    5e4d:	64 48 33 3c 25 28 00 	xor    rdi,QWORD PTR fs:0x28
    5e54:	00 00 
    5e56:	74 05                	je     5e5d <secp256k1_algebra_verify+0xa2>
    5e58:	e8 93 b8 ff ff       	call   16f0 <__stack_chk_fail@plt>
    5e5d:	c9                   	leave  
    5e5e:	c3                   	ret    

0000000000005e5f <secp256k1_algebra_verify_sum>:
    5e5f:	55                   	push   rbp
    5e60:	48 89 e5             	mov    rbp,rsp
    5e63:	48 83 ec 60          	sub    rsp,0x60
    5e67:	48 89 7d c8          	mov    QWORD PTR [rbp-0x38],rdi
    5e6b:	48 89 75 c0          	mov    QWORD PTR [rbp-0x40],rsi
    5e6f:	48 89 55 b8          	mov    QWORD PTR [rbp-0x48],rdx
    5e73:	89 4d b4             	mov    DWORD PTR [rbp-0x4c],ecx
    5e76:	4c 89 45 a8          	mov    QWORD PTR [rbp-0x58],r8
    5e7a:	48 c7 45 e0 00 00 00 	mov    QWORD PTR [rbp-0x20],0x0
    5e81:	00 
    5e82:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
    5e89:	00 
    5e8a:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
    5e91:	00 
    5e92:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
    5e99:	00 
    5e9a:	c7 45 d4 ff ff ff ff 	mov    DWORD PTR [rbp-0x2c],0xffffffff
    5ea1:	48 83 7d c8 00       	cmp    QWORD PTR [rbp-0x38],0x0
    5ea6:	74 1b                	je     5ec3 <secp256k1_algebra_verify_sum+0x64>
    5ea8:	48 83 7d c0 00       	cmp    QWORD PTR [rbp-0x40],0x0
    5ead:	74 14                	je     5ec3 <secp256k1_algebra_verify_sum+0x64>
    5eaf:	48 83 7d b8 00       	cmp    QWORD PTR [rbp-0x48],0x0
    5eb4:	74 0d                	je     5ec3 <secp256k1_algebra_verify_sum+0x64>
    5eb6:	83 7d b4 00          	cmp    DWORD PTR [rbp-0x4c],0x0
    5eba:	74 07                	je     5ec3 <secp256k1_algebra_verify_sum+0x64>
    5ebc:	48 83 7d a8 00       	cmp    QWORD PTR [rbp-0x58],0x0
    5ec1:	75 0a                	jne    5ecd <secp256k1_algebra_verify_sum+0x6e>
    5ec3:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    5ec8:	e9 1f 02 00 00       	jmp    60ec <secp256k1_algebra_verify_sum+0x28d>
    5ecd:	48 8b 45 a8          	mov    rax,QWORD PTR [rbp-0x58]
    5ed1:	c6 00 00             	mov    BYTE PTR [rax],0x0
    5ed4:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    5ed8:	48 8b 00             	mov    rax,QWORD PTR [rax]
    5edb:	48 89 c7             	mov    rdi,rax
    5ede:	e8 bd b6 ff ff       	call   15a0 <EC_POINT_new@plt>
    5ee3:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
    5ee7:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
    5eec:	75 0a                	jne    5ef8 <secp256k1_algebra_verify_sum+0x99>
    5eee:	b8 fc ff ff ff       	mov    eax,0xfffffffc
    5ef3:	e9 f4 01 00 00       	jmp    60ec <secp256k1_algebra_verify_sum+0x28d>
    5ef8:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    5efc:	48 8b 00             	mov    rax,QWORD PTR [rax]
    5eff:	48 89 c7             	mov    rdi,rax
    5f02:	e8 99 b6 ff ff       	call   15a0 <EC_POINT_new@plt>
    5f07:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    5f0b:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    5f10:	75 0c                	jne    5f1e <secp256k1_algebra_verify_sum+0xbf>
    5f12:	c7 45 d4 fc ff ff ff 	mov    DWORD PTR [rbp-0x2c],0xfffffffc
    5f19:	e9 8f 01 00 00       	jmp    60ad <secp256k1_algebra_verify_sum+0x24e>
    5f1e:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    5f22:	48 8b 00             	mov    rax,QWORD PTR [rax]
    5f25:	48 89 c7             	mov    rdi,rax
    5f28:	e8 73 b6 ff ff       	call   15a0 <EC_POINT_new@plt>
    5f2d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
    5f31:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
    5f36:	75 0c                	jne    5f44 <secp256k1_algebra_verify_sum+0xe5>
    5f38:	c7 45 d4 fc ff ff ff 	mov    DWORD PTR [rbp-0x2c],0xfffffffc
    5f3f:	e9 69 01 00 00       	jmp    60ad <secp256k1_algebra_verify_sum+0x24e>
    5f44:	e8 87 b7 ff ff       	call   16d0 <BN_CTX_new@plt>
    5f49:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
    5f4d:	48 83 7d e0 00       	cmp    QWORD PTR [rbp-0x20],0x0
    5f52:	75 0c                	jne    5f60 <secp256k1_algebra_verify_sum+0x101>
    5f54:	c7 45 d4 fc ff ff ff 	mov    DWORD PTR [rbp-0x2c],0xfffffffc
    5f5b:	e9 4d 01 00 00       	jmp    60ad <secp256k1_algebra_verify_sum+0x24e>
    5f60:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
    5f64:	48 89 c7             	mov    rdi,rax
    5f67:	e8 94 b8 ff ff       	call   1800 <BN_CTX_start@plt>
    5f6c:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
    5f70:	0f b6 00             	movzx  eax,BYTE PTR [rax]
    5f73:	84 c0                	test   al,al
    5f75:	74 07                	je     5f7e <secp256k1_algebra_verify_sum+0x11f>
    5f77:	bf 21 00 00 00       	mov    edi,0x21
    5f7c:	eb 05                	jmp    5f83 <secp256k1_algebra_verify_sum+0x124>
    5f7e:	bf 01 00 00 00       	mov    edi,0x1
    5f83:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    5f87:	48 8b 00             	mov    rax,QWORD PTR [rax]
    5f8a:	48 8b 4d e0          	mov    rcx,QWORD PTR [rbp-0x20]
    5f8e:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
    5f92:	48 8b 75 f0          	mov    rsi,QWORD PTR [rbp-0x10]
    5f96:	49 89 c8             	mov    r8,rcx
    5f99:	48 89 f9             	mov    rcx,rdi
    5f9c:	48 89 c7             	mov    rdi,rax
    5f9f:	e8 9c b7 ff ff       	call   1740 <EC_POINT_oct2point@plt>
    5fa4:	85 c0                	test   eax,eax
    5fa6:	75 15                	jne    5fbd <secp256k1_algebra_verify_sum+0x15e>
    5fa8:	e8 f3 b4 ff ff       	call   14a0 <ERR_get_error@plt>
    5fad:	48 89 c7             	mov    rdi,rax
    5fb0:	e8 11 fc ff ff       	call   5bc6 <from_openssl_error>
    5fb5:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
    5fb8:	e9 f0 00 00 00       	jmp    60ad <secp256k1_algebra_verify_sum+0x24e>
    5fbd:	c7 45 d8 00 00 00 00 	mov    DWORD PTR [rbp-0x28],0x0
    5fc4:	e9 98 00 00 00       	jmp    6061 <secp256k1_algebra_verify_sum+0x202>
    5fc9:	8b 55 d8             	mov    edx,DWORD PTR [rbp-0x28]
    5fcc:	48 89 d0             	mov    rax,rdx
    5fcf:	48 c1 e0 05          	shl    rax,0x5
    5fd3:	48 01 c2             	add    rdx,rax
    5fd6:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
    5fda:	48 01 d0             	add    rax,rdx
    5fdd:	0f b6 00             	movzx  eax,BYTE PTR [rax]
    5fe0:	84 c0                	test   al,al
    5fe2:	74 07                	je     5feb <secp256k1_algebra_verify_sum+0x18c>
    5fe4:	bf 21 00 00 00       	mov    edi,0x21
    5fe9:	eb 05                	jmp    5ff0 <secp256k1_algebra_verify_sum+0x191>
    5feb:	bf 01 00 00 00       	mov    edi,0x1
    5ff0:	8b 55 d8             	mov    edx,DWORD PTR [rbp-0x28]
    5ff3:	48 89 d0             	mov    rax,rdx
    5ff6:	48 c1 e0 05          	shl    rax,0x5
    5ffa:	48 01 c2             	add    rdx,rax
    5ffd:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
    6001:	48 01 c2             	add    rdx,rax
    6004:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    6008:	48 8b 00             	mov    rax,QWORD PTR [rax]
    600b:	48 8b 4d e0          	mov    rcx,QWORD PTR [rbp-0x20]
    600f:	48 8b 75 e8          	mov    rsi,QWORD PTR [rbp-0x18]
    6013:	49 89 c8             	mov    r8,rcx
    6016:	48 89 f9             	mov    rcx,rdi
    6019:	48 89 c7             	mov    rdi,rax
    601c:	e8 1f b7 ff ff       	call   1740 <EC_POINT_oct2point@plt>
    6021:	85 c0                	test   eax,eax
    6023:	75 12                	jne    6037 <secp256k1_algebra_verify_sum+0x1d8>
    6025:	e8 76 b4 ff ff       	call   14a0 <ERR_get_error@plt>
    602a:	48 89 c7             	mov    rdi,rax
    602d:	e8 94 fb ff ff       	call   5bc6 <from_openssl_error>
    6032:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
    6035:	eb 76                	jmp    60ad <secp256k1_algebra_verify_sum+0x24e>
    6037:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    603b:	48 8b 00             	mov    rax,QWORD PTR [rax]
    603e:	48 8b 7d e0          	mov    rdi,QWORD PTR [rbp-0x20]
    6042:	48 8b 4d e8          	mov    rcx,QWORD PTR [rbp-0x18]
    6046:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
    604a:	48 8b 75 f8          	mov    rsi,QWORD PTR [rbp-0x8]
    604e:	49 89 f8             	mov    r8,rdi
    6051:	48 89 c7             	mov    rdi,rax
    6054:	e8 87 b7 ff ff       	call   17e0 <EC_POINT_add@plt>
    6059:	85 c0                	test   eax,eax
    605b:	74 4c                	je     60a9 <secp256k1_algebra_verify_sum+0x24a>
    605d:	83 45 d8 01          	add    DWORD PTR [rbp-0x28],0x1
    6061:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
    6064:	3b 45 b4             	cmp    eax,DWORD PTR [rbp-0x4c]
    6067:	0f 82 5c ff ff ff    	jb     5fc9 <secp256k1_algebra_verify_sum+0x16a>
    606d:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    6071:	48 8b 00             	mov    rax,QWORD PTR [rax]
    6074:	48 8b 4d e0          	mov    rcx,QWORD PTR [rbp-0x20]
    6078:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
    607c:	48 8b 75 f8          	mov    rsi,QWORD PTR [rbp-0x8]
    6080:	48 89 c7             	mov    rdi,rax
    6083:	e8 08 b6 ff ff       	call   1690 <EC_POINT_cmp@plt>
    6088:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
    608b:	83 7d dc 00          	cmp    DWORD PTR [rbp-0x24],0x0
    608f:	78 1b                	js     60ac <secp256k1_algebra_verify_sum+0x24d>
    6091:	83 7d dc 00          	cmp    DWORD PTR [rbp-0x24],0x0
    6095:	0f 94 c0             	sete   al
    6098:	89 c2                	mov    edx,eax
    609a:	48 8b 45 a8          	mov    rax,QWORD PTR [rbp-0x58]
    609e:	88 10                	mov    BYTE PTR [rax],dl
    60a0:	c7 45 d4 00 00 00 00 	mov    DWORD PTR [rbp-0x2c],0x0
    60a7:	eb 04                	jmp    60ad <secp256k1_algebra_verify_sum+0x24e>
    60a9:	90                   	nop
    60aa:	eb 01                	jmp    60ad <secp256k1_algebra_verify_sum+0x24e>
    60ac:	90                   	nop
    60ad:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
    60b1:	48 89 c7             	mov    rdi,rax
    60b4:	e8 17 b7 ff ff       	call   17d0 <BN_CTX_end@plt>
    60b9:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
    60bd:	48 89 c7             	mov    rdi,rax
    60c0:	e8 0b b4 ff ff       	call   14d0 <BN_CTX_free@plt>
    60c5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    60c9:	48 89 c7             	mov    rdi,rax
    60cc:	e8 7f b6 ff ff       	call   1750 <EC_POINT_free@plt>
    60d1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    60d5:	48 89 c7             	mov    rdi,rax
    60d8:	e8 73 b6 ff ff       	call   1750 <EC_POINT_free@plt>
    60dd:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    60e1:	48 89 c7             	mov    rdi,rax
    60e4:	e8 67 b6 ff ff       	call   1750 <EC_POINT_free@plt>
    60e9:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
    60ec:	c9                   	leave  
    60ed:	c3                   	ret    

00000000000060ee <secp256k1_algebra_verify_linear_combination>:
    60ee:	55                   	push   rbp
    60ef:	48 89 e5             	mov    rbp,rsp
    60f2:	53                   	push   rbx
    60f3:	48 81 ec 98 00 00 00 	sub    rsp,0x98
    60fa:	48 89 7d 88          	mov    QWORD PTR [rbp-0x78],rdi
    60fe:	48 89 75 80          	mov    QWORD PTR [rbp-0x80],rsi
    6102:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
    6109:	48 89 8d 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rcx
    6110:	44 89 85 6c ff ff ff 	mov    DWORD PTR [rbp-0x94],r8d
    6117:	4c 89 8d 60 ff ff ff 	mov    QWORD PTR [rbp-0xa0],r9
    611e:	48 c7 45 d8 00 00 00 	mov    QWORD PTR [rbp-0x28],0x0
    6125:	00 
    6126:	48 c7 45 e0 00 00 00 	mov    QWORD PTR [rbp-0x20],0x0
    612d:	00 
    612e:	48 c7 45 a0 00 00 00 	mov    QWORD PTR [rbp-0x60],0x0
    6135:	00 
    6136:	48 c7 45 a8 00 00 00 	mov    QWORD PTR [rbp-0x58],0x0
    613d:	00 
    613e:	48 c7 45 b0 00 00 00 	mov    QWORD PTR [rbp-0x50],0x0
    6145:	00 
    6146:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
    614d:	00 
    614e:	c7 45 98 fc ff ff ff 	mov    DWORD PTR [rbp-0x68],0xfffffffc
    6155:	48 83 7d 88 00       	cmp    QWORD PTR [rbp-0x78],0x0
    615a:	74 2e                	je     618a <secp256k1_algebra_verify_linear_combination+0x9c>
    615c:	48 83 7d 80 00       	cmp    QWORD PTR [rbp-0x80],0x0
    6161:	74 27                	je     618a <secp256k1_algebra_verify_linear_combination+0x9c>
    6163:	48 83 bd 78 ff ff ff 	cmp    QWORD PTR [rbp-0x88],0x0
    616a:	00 
    616b:	74 1d                	je     618a <secp256k1_algebra_verify_linear_combination+0x9c>
    616d:	48 83 bd 70 ff ff ff 	cmp    QWORD PTR [rbp-0x90],0x0
    6174:	00 
    6175:	74 13                	je     618a <secp256k1_algebra_verify_linear_combination+0x9c>
    6177:	83 bd 6c ff ff ff 00 	cmp    DWORD PTR [rbp-0x94],0x0
    617e:	74 0a                	je     618a <secp256k1_algebra_verify_linear_combination+0x9c>
    6180:	48 83 bd 60 ff ff ff 	cmp    QWORD PTR [rbp-0xa0],0x0
    6187:	00 
    6188:	75 0a                	jne    6194 <secp256k1_algebra_verify_linear_combination+0xa6>
    618a:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    618f:	e9 35 04 00 00       	jmp    65c9 <secp256k1_algebra_verify_linear_combination+0x4db>
    6194:	48 8b 85 60 ff ff ff 	mov    rax,QWORD PTR [rbp-0xa0]
    619b:	c6 00 00             	mov    BYTE PTR [rax],0x0
    619e:	e8 2d b5 ff ff       	call   16d0 <BN_CTX_new@plt>
    61a3:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
    61a7:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
    61ac:	75 0a                	jne    61b8 <secp256k1_algebra_verify_linear_combination+0xca>
    61ae:	b8 fc ff ff ff       	mov    eax,0xfffffffc
    61b3:	e9 11 04 00 00       	jmp    65c9 <secp256k1_algebra_verify_linear_combination+0x4db>
    61b8:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    61bc:	48 89 c7             	mov    rdi,rax
    61bf:	e8 3c b6 ff ff       	call   1800 <BN_CTX_start@plt>
    61c4:	48 8b 45 88          	mov    rax,QWORD PTR [rbp-0x78]
    61c8:	48 8b 00             	mov    rax,QWORD PTR [rax]
    61cb:	48 89 c7             	mov    rdi,rax
    61ce:	e8 cd b3 ff ff       	call   15a0 <EC_POINT_new@plt>
    61d3:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
    61d7:	48 83 7d e0 00       	cmp    QWORD PTR [rbp-0x20],0x0
    61dc:	0f 84 fb 02 00 00    	je     64dd <secp256k1_algebra_verify_linear_combination+0x3ef>
    61e2:	48 8b 45 80          	mov    rax,QWORD PTR [rbp-0x80]
    61e6:	0f b6 00             	movzx  eax,BYTE PTR [rax]
    61e9:	84 c0                	test   al,al
    61eb:	74 07                	je     61f4 <secp256k1_algebra_verify_linear_combination+0x106>
    61ed:	bf 21 00 00 00       	mov    edi,0x21
    61f2:	eb 05                	jmp    61f9 <secp256k1_algebra_verify_linear_combination+0x10b>
    61f4:	bf 01 00 00 00       	mov    edi,0x1
    61f9:	48 8b 45 88          	mov    rax,QWORD PTR [rbp-0x78]
    61fd:	48 8b 00             	mov    rax,QWORD PTR [rax]
    6200:	48 8b 4d d8          	mov    rcx,QWORD PTR [rbp-0x28]
    6204:	48 8b 55 80          	mov    rdx,QWORD PTR [rbp-0x80]
    6208:	48 8b 75 e0          	mov    rsi,QWORD PTR [rbp-0x20]
    620c:	49 89 c8             	mov    r8,rcx
    620f:	48 89 f9             	mov    rcx,rdi
    6212:	48 89 c7             	mov    rdi,rax
    6215:	e8 26 b5 ff ff       	call   1740 <EC_POINT_oct2point@plt>
    621a:	85 c0                	test   eax,eax
    621c:	75 15                	jne    6233 <secp256k1_algebra_verify_linear_combination+0x145>
    621e:	e8 7d b2 ff ff       	call   14a0 <ERR_get_error@plt>
    6223:	48 89 c7             	mov    rdi,rax
    6226:	e8 9b f9 ff ff       	call   5bc6 <from_openssl_error>
    622b:	89 45 98             	mov    DWORD PTR [rbp-0x68],eax
    622e:	e9 b7 02 00 00       	jmp    64ea <secp256k1_algebra_verify_linear_combination+0x3fc>
    6233:	8b 85 6c ff ff ff    	mov    eax,DWORD PTR [rbp-0x94]
    6239:	be 08 00 00 00       	mov    esi,0x8
    623e:	48 89 c7             	mov    rdi,rax
    6241:	e8 da b4 ff ff       	call   1720 <calloc@plt>
    6246:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
    624a:	48 83 7d a0 00       	cmp    QWORD PTR [rbp-0x60],0x0
    624f:	0f 84 8b 02 00 00    	je     64e0 <secp256k1_algebra_verify_linear_combination+0x3f2>
    6255:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
    625c:	00 
    625d:	e9 d5 00 00 00       	jmp    6337 <secp256k1_algebra_verify_linear_combination+0x249>
    6262:	48 8b 45 88          	mov    rax,QWORD PTR [rbp-0x78]
    6266:	48 8b 00             	mov    rax,QWORD PTR [rax]
    6269:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
    626d:	48 8d 0c d5 00 00 00 	lea    rcx,[rdx*8+0x0]
    6274:	00 
    6275:	48 8b 55 a0          	mov    rdx,QWORD PTR [rbp-0x60]
    6279:	48 8d 1c 11          	lea    rbx,[rcx+rdx*1]
    627d:	48 89 c7             	mov    rdi,rax
    6280:	e8 1b b3 ff ff       	call   15a0 <EC_POINT_new@plt>
    6285:	48 89 03             	mov    QWORD PTR [rbx],rax
    6288:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
    628c:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
    6293:	00 
    6294:	48 8b 45 a0          	mov    rax,QWORD PTR [rbp-0x60]
    6298:	48 01 d0             	add    rax,rdx
    629b:	48 8b 00             	mov    rax,QWORD PTR [rax]
    629e:	48 85 c0             	test   rax,rax
    62a1:	0f 84 3c 02 00 00    	je     64e3 <secp256k1_algebra_verify_linear_combination+0x3f5>
    62a7:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
    62ab:	48 89 d0             	mov    rax,rdx
    62ae:	48 c1 e0 05          	shl    rax,0x5
    62b2:	48 01 c2             	add    rdx,rax
    62b5:	48 8b 85 78 ff ff ff 	mov    rax,QWORD PTR [rbp-0x88]
    62bc:	48 01 d0             	add    rax,rdx
    62bf:	0f b6 00             	movzx  eax,BYTE PTR [rax]
    62c2:	84 c0                	test   al,al
    62c4:	74 07                	je     62cd <secp256k1_algebra_verify_linear_combination+0x1df>
    62c6:	bf 21 00 00 00       	mov    edi,0x21
    62cb:	eb 05                	jmp    62d2 <secp256k1_algebra_verify_linear_combination+0x1e4>
    62cd:	bf 01 00 00 00       	mov    edi,0x1
    62d2:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
    62d6:	48 89 d0             	mov    rax,rdx
    62d9:	48 c1 e0 05          	shl    rax,0x5
    62dd:	48 01 c2             	add    rdx,rax
    62e0:	48 8b 85 78 ff ff ff 	mov    rax,QWORD PTR [rbp-0x88]
    62e7:	48 01 c2             	add    rdx,rax
    62ea:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
    62ee:	48 8d 0c c5 00 00 00 	lea    rcx,[rax*8+0x0]
    62f5:	00 
    62f6:	48 8b 45 a0          	mov    rax,QWORD PTR [rbp-0x60]
    62fa:	48 01 c8             	add    rax,rcx
    62fd:	48 8b 30             	mov    rsi,QWORD PTR [rax]
    6300:	48 8b 45 88          	mov    rax,QWORD PTR [rbp-0x78]
    6304:	48 8b 00             	mov    rax,QWORD PTR [rax]
    6307:	48 8b 4d d8          	mov    rcx,QWORD PTR [rbp-0x28]
    630b:	49 89 c8             	mov    r8,rcx
    630e:	48 89 f9             	mov    rcx,rdi
    6311:	48 89 c7             	mov    rdi,rax
    6314:	e8 27 b4 ff ff       	call   1740 <EC_POINT_oct2point@plt>
    6319:	85 c0                	test   eax,eax
    631b:	75 15                	jne    6332 <secp256k1_algebra_verify_linear_combination+0x244>
    631d:	e8 7e b1 ff ff       	call   14a0 <ERR_get_error@plt>
    6322:	48 89 c7             	mov    rdi,rax
    6325:	e8 9c f8 ff ff       	call   5bc6 <from_openssl_error>
    632a:	89 45 98             	mov    DWORD PTR [rbp-0x68],eax
    632d:	e9 b8 01 00 00       	jmp    64ea <secp256k1_algebra_verify_linear_combination+0x3fc>
    6332:	48 83 45 b8 01       	add    QWORD PTR [rbp-0x48],0x1
    6337:	8b 85 6c ff ff ff    	mov    eax,DWORD PTR [rbp-0x94]
    633d:	48 39 45 b8          	cmp    QWORD PTR [rbp-0x48],rax
    6341:	0f 82 1b ff ff ff    	jb     6262 <secp256k1_algebra_verify_linear_combination+0x174>
    6347:	8b 85 6c ff ff ff    	mov    eax,DWORD PTR [rbp-0x94]
    634d:	be 08 00 00 00       	mov    esi,0x8
    6352:	48 89 c7             	mov    rdi,rax
    6355:	e8 c6 b3 ff ff       	call   1720 <calloc@plt>
    635a:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
    635e:	48 83 7d a8 00       	cmp    QWORD PTR [rbp-0x58],0x0
    6363:	0f 84 7d 01 00 00    	je     64e6 <secp256k1_algebra_verify_linear_combination+0x3f8>
    6369:	48 c7 45 c0 00 00 00 	mov    QWORD PTR [rbp-0x40],0x0
    6370:	00 
    6371:	e9 8b 00 00 00       	jmp    6401 <secp256k1_algebra_verify_linear_combination+0x313>
    6376:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
    637a:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
    6381:	00 
    6382:	48 8b 45 a8          	mov    rax,QWORD PTR [rbp-0x58]
    6386:	48 8d 1c 02          	lea    rbx,[rdx+rax*1]
    638a:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    638e:	48 89 c7             	mov    rdi,rax
    6391:	e8 da b3 ff ff       	call   1770 <BN_CTX_get@plt>
    6396:	48 89 03             	mov    QWORD PTR [rbx],rax
    6399:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
    639d:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
    63a4:	00 
    63a5:	48 8b 45 a8          	mov    rax,QWORD PTR [rbp-0x58]
    63a9:	48 01 d0             	add    rax,rdx
    63ac:	48 8b 00             	mov    rax,QWORD PTR [rax]
    63af:	48 85 c0             	test   rax,rax
    63b2:	0f 84 31 01 00 00    	je     64e9 <secp256k1_algebra_verify_linear_combination+0x3fb>
    63b8:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
    63bc:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
    63c3:	00 
    63c4:	48 8b 45 a8          	mov    rax,QWORD PTR [rbp-0x58]
    63c8:	48 01 d0             	add    rax,rdx
    63cb:	48 8b 00             	mov    rax,QWORD PTR [rax]
    63ce:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
    63d2:	48 89 d1             	mov    rcx,rdx
    63d5:	48 c1 e1 05          	shl    rcx,0x5
    63d9:	48 8b 95 70 ff ff ff 	mov    rdx,QWORD PTR [rbp-0x90]
    63e0:	48 01 d1             	add    rcx,rdx
    63e3:	48 89 c2             	mov    rdx,rax
    63e6:	be 20 00 00 00       	mov    esi,0x20
    63eb:	48 89 cf             	mov    rdi,rcx
    63ee:	e8 8d b1 ff ff       	call   1580 <BN_bin2bn@plt>
    63f3:	48 85 c0             	test   rax,rax
    63f6:	0f 84 ed 00 00 00    	je     64e9 <secp256k1_algebra_verify_linear_combination+0x3fb>
    63fc:	48 83 45 c0 01       	add    QWORD PTR [rbp-0x40],0x1
    6401:	8b 85 6c ff ff ff    	mov    eax,DWORD PTR [rbp-0x94]
    6407:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
    640b:	0f 82 65 ff ff ff    	jb     6376 <secp256k1_algebra_verify_linear_combination+0x288>
    6411:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    6415:	48 89 c7             	mov    rdi,rax
    6418:	e8 53 b3 ff ff       	call   1770 <BN_CTX_get@plt>
    641d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
    6421:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    6425:	be 00 00 00 00       	mov    esi,0x0
    642a:	48 89 c7             	mov    rdi,rax
    642d:	e8 3e b1 ff ff       	call   1570 <BN_set_word@plt>
    6432:	48 8b 45 88          	mov    rax,QWORD PTR [rbp-0x78]
    6436:	48 8b 00             	mov    rax,QWORD PTR [rax]
    6439:	48 89 c7             	mov    rdi,rax
    643c:	e8 5f b1 ff ff       	call   15a0 <EC_POINT_new@plt>
    6441:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
    6445:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
    644a:	0f 84 99 00 00 00    	je     64e9 <secp256k1_algebra_verify_linear_combination+0x3fb>
    6450:	48 83 7d b0 00       	cmp    QWORD PTR [rbp-0x50],0x0
    6455:	0f 84 8e 00 00 00    	je     64e9 <secp256k1_algebra_verify_linear_combination+0x3fb>
    645b:	8b 8d 6c ff ff ff    	mov    ecx,DWORD PTR [rbp-0x94]
    6461:	48 8b 45 88          	mov    rax,QWORD PTR [rbp-0x78]
    6465:	48 8b 00             	mov    rax,QWORD PTR [rax]
    6468:	4c 8b 45 a8          	mov    r8,QWORD PTR [rbp-0x58]
    646c:	48 8b 7d a0          	mov    rdi,QWORD PTR [rbp-0x60]
    6470:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
    6474:	48 8b 75 b0          	mov    rsi,QWORD PTR [rbp-0x50]
    6478:	48 83 ec 08          	sub    rsp,0x8
    647c:	ff 75 d8             	push   QWORD PTR [rbp-0x28]
    647f:	4d 89 c1             	mov    r9,r8
    6482:	49 89 f8             	mov    r8,rdi
    6485:	48 89 c7             	mov    rdi,rax
    6488:	e8 83 b2 ff ff       	call   1710 <EC_POINTs_mul@plt>
    648d:	48 83 c4 10          	add    rsp,0x10
    6491:	85 c0                	test   eax,eax
    6493:	75 09                	jne    649e <secp256k1_algebra_verify_linear_combination+0x3b0>
    6495:	c7 45 98 ff ff ff ff 	mov    DWORD PTR [rbp-0x68],0xffffffff
    649c:	eb 4c                	jmp    64ea <secp256k1_algebra_verify_linear_combination+0x3fc>
    649e:	48 8b 45 88          	mov    rax,QWORD PTR [rbp-0x78]
    64a2:	48 8b 00             	mov    rax,QWORD PTR [rax]
    64a5:	48 8b 4d d8          	mov    rcx,QWORD PTR [rbp-0x28]
    64a9:	48 8b 55 e0          	mov    rdx,QWORD PTR [rbp-0x20]
    64ad:	48 8b 75 b0          	mov    rsi,QWORD PTR [rbp-0x50]
    64b1:	48 89 c7             	mov    rdi,rax
    64b4:	e8 d7 b1 ff ff       	call   1690 <EC_POINT_cmp@plt>
    64b9:	89 45 9c             	mov    DWORD PTR [rbp-0x64],eax
    64bc:	83 7d 9c 00          	cmp    DWORD PTR [rbp-0x64],0x0
    64c0:	78 27                	js     64e9 <secp256k1_algebra_verify_linear_combination+0x3fb>
    64c2:	83 7d 9c 00          	cmp    DWORD PTR [rbp-0x64],0x0
    64c6:	0f 94 c0             	sete   al
    64c9:	89 c2                	mov    edx,eax
    64cb:	48 8b 85 60 ff ff ff 	mov    rax,QWORD PTR [rbp-0xa0]
    64d2:	88 10                	mov    BYTE PTR [rax],dl
    64d4:	c7 45 98 00 00 00 00 	mov    DWORD PTR [rbp-0x68],0x0
    64db:	eb 0d                	jmp    64ea <secp256k1_algebra_verify_linear_combination+0x3fc>
    64dd:	90                   	nop
    64de:	eb 0a                	jmp    64ea <secp256k1_algebra_verify_linear_combination+0x3fc>
    64e0:	90                   	nop
    64e1:	eb 07                	jmp    64ea <secp256k1_algebra_verify_linear_combination+0x3fc>
    64e3:	90                   	nop
    64e4:	eb 04                	jmp    64ea <secp256k1_algebra_verify_linear_combination+0x3fc>
    64e6:	90                   	nop
    64e7:	eb 01                	jmp    64ea <secp256k1_algebra_verify_linear_combination+0x3fc>
    64e9:	90                   	nop
    64ea:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
    64f1:	00 
    64f2:	eb 3e                	jmp    6532 <secp256k1_algebra_verify_linear_combination+0x444>
    64f4:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    64f8:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
    64ff:	00 
    6500:	48 8b 45 a8          	mov    rax,QWORD PTR [rbp-0x58]
    6504:	48 01 d0             	add    rax,rdx
    6507:	48 8b 00             	mov    rax,QWORD PTR [rax]
    650a:	48 85 c0             	test   rax,rax
    650d:	74 1e                	je     652d <secp256k1_algebra_verify_linear_combination+0x43f>
    650f:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    6513:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
    651a:	00 
    651b:	48 8b 45 a8          	mov    rax,QWORD PTR [rbp-0x58]
    651f:	48 01 d0             	add    rax,rdx
    6522:	48 8b 00             	mov    rax,QWORD PTR [rax]
    6525:	48 89 c7             	mov    rdi,rax
    6528:	e8 43 b1 ff ff       	call   1670 <BN_clear@plt>
    652d:	48 83 45 c8 01       	add    QWORD PTR [rbp-0x38],0x1
    6532:	8b 85 6c ff ff ff    	mov    eax,DWORD PTR [rbp-0x94]
    6538:	48 39 45 c8          	cmp    QWORD PTR [rbp-0x38],rax
    653c:	72 b6                	jb     64f4 <secp256k1_algebra_verify_linear_combination+0x406>
    653e:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    6542:	48 89 c7             	mov    rdi,rax
    6545:	e8 86 b2 ff ff       	call   17d0 <BN_CTX_end@plt>
    654a:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    654e:	48 89 c7             	mov    rdi,rax
    6551:	e8 7a af ff ff       	call   14d0 <BN_CTX_free@plt>
    6556:	48 83 7d a0 00       	cmp    QWORD PTR [rbp-0x60],0x0
    655b:	74 45                	je     65a2 <secp256k1_algebra_verify_linear_combination+0x4b4>
    655d:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
    6564:	00 
    6565:	eb 23                	jmp    658a <secp256k1_algebra_verify_linear_combination+0x49c>
    6567:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
    656b:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
    6572:	00 
    6573:	48 8b 45 a0          	mov    rax,QWORD PTR [rbp-0x60]
    6577:	48 01 d0             	add    rax,rdx
    657a:	48 8b 00             	mov    rax,QWORD PTR [rax]
    657d:	48 89 c7             	mov    rdi,rax
    6580:	e8 cb b1 ff ff       	call   1750 <EC_POINT_free@plt>
    6585:	48 83 45 d0 01       	add    QWORD PTR [rbp-0x30],0x1
    658a:	8b 85 6c ff ff ff    	mov    eax,DWORD PTR [rbp-0x94]
    6590:	48 39 45 d0          	cmp    QWORD PTR [rbp-0x30],rax
    6594:	72 d1                	jb     6567 <secp256k1_algebra_verify_linear_combination+0x479>
    6596:	48 8b 45 a0          	mov    rax,QWORD PTR [rbp-0x60]
    659a:	48 89 c7             	mov    rdi,rax
    659d:	e8 7e b0 ff ff       	call   1620 <free@plt>
    65a2:	48 8b 45 a8          	mov    rax,QWORD PTR [rbp-0x58]
    65a6:	48 89 c7             	mov    rdi,rax
    65a9:	e8 72 b0 ff ff       	call   1620 <free@plt>
    65ae:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
    65b2:	48 89 c7             	mov    rdi,rax
    65b5:	e8 96 b1 ff ff       	call   1750 <EC_POINT_free@plt>
    65ba:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
    65be:	48 89 c7             	mov    rdi,rax
    65c1:	e8 8a b1 ff ff       	call   1750 <EC_POINT_free@plt>
    65c6:	8b 45 98             	mov    eax,DWORD PTR [rbp-0x68]
    65c9:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
    65cd:	c9                   	leave  
    65ce:	c3                   	ret    

00000000000065cf <secp256k1_algebra_generator_mul>:
    65cf:	55                   	push   rbp
    65d0:	48 89 e5             	mov    rbp,rsp
    65d3:	48 83 ec 20          	sub    rsp,0x20
    65d7:	48 89 7d f8          	mov    QWORD PTR [rbp-0x8],rdi
    65db:	48 89 75 f0          	mov    QWORD PTR [rbp-0x10],rsi
    65df:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
    65e3:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
    65e8:	75 07                	jne    65f1 <secp256k1_algebra_generator_mul+0x22>
    65ea:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    65ef:	eb 1c                	jmp    660d <secp256k1_algebra_generator_mul+0x3e>
    65f1:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
    65f5:	48 8b 75 e8          	mov    rsi,QWORD PTR [rbp-0x18]
    65f9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    65fd:	48 89 d1             	mov    rcx,rdx
    6600:	ba 20 00 00 00       	mov    edx,0x20
    6605:	48 89 c7             	mov    rdi,rax
    6608:	e8 10 f6 ff ff       	call   5c1d <secp256k1_algebra_generate_proof_for_data>
    660d:	c9                   	leave  
    660e:	c3                   	ret    

000000000000660f <secp256k1_algebra_add_points>:
    660f:	55                   	push   rbp
    6610:	48 89 e5             	mov    rbp,rsp
    6613:	48 83 ec 40          	sub    rsp,0x40
    6617:	48 89 7d d8          	mov    QWORD PTR [rbp-0x28],rdi
    661b:	48 89 75 d0          	mov    QWORD PTR [rbp-0x30],rsi
    661f:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
    6623:	48 89 4d c0          	mov    QWORD PTR [rbp-0x40],rcx
    6627:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
    662e:	00 
    662f:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
    6636:	00 
    6637:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
    663e:	00 
    663f:	c7 45 e4 ff ff ff ff 	mov    DWORD PTR [rbp-0x1c],0xffffffff
    6646:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
    664b:	74 15                	je     6662 <secp256k1_algebra_add_points+0x53>
    664d:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
    6652:	74 0e                	je     6662 <secp256k1_algebra_add_points+0x53>
    6654:	48 83 7d c8 00       	cmp    QWORD PTR [rbp-0x38],0x0
    6659:	74 07                	je     6662 <secp256k1_algebra_add_points+0x53>
    665b:	48 83 7d c0 00       	cmp    QWORD PTR [rbp-0x40],0x0
    6660:	75 0a                	jne    666c <secp256k1_algebra_add_points+0x5d>
    6662:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    6667:	e9 be 01 00 00       	jmp    682a <secp256k1_algebra_add_points+0x21b>
    666c:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    6670:	48 8b 00             	mov    rax,QWORD PTR [rax]
    6673:	48 89 c7             	mov    rdi,rax
    6676:	e8 25 af ff ff       	call   15a0 <EC_POINT_new@plt>
    667b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
    667f:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
    6684:	75 0a                	jne    6690 <secp256k1_algebra_add_points+0x81>
    6686:	b8 fc ff ff ff       	mov    eax,0xfffffffc
    668b:	e9 9a 01 00 00       	jmp    682a <secp256k1_algebra_add_points+0x21b>
    6690:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    6694:	48 8b 00             	mov    rax,QWORD PTR [rax]
    6697:	48 89 c7             	mov    rdi,rax
    669a:	e8 01 af ff ff       	call   15a0 <EC_POINT_new@plt>
    669f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    66a3:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    66a8:	75 0c                	jne    66b6 <secp256k1_algebra_add_points+0xa7>
    66aa:	c7 45 e4 fc ff ff ff 	mov    DWORD PTR [rbp-0x1c],0xfffffffc
    66b1:	e9 41 01 00 00       	jmp    67f7 <secp256k1_algebra_add_points+0x1e8>
    66b6:	e8 15 b0 ff ff       	call   16d0 <BN_CTX_new@plt>
    66bb:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
    66bf:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
    66c4:	75 0c                	jne    66d2 <secp256k1_algebra_add_points+0xc3>
    66c6:	c7 45 e4 fc ff ff ff 	mov    DWORD PTR [rbp-0x1c],0xfffffffc
    66cd:	e9 25 01 00 00       	jmp    67f7 <secp256k1_algebra_add_points+0x1e8>
    66d2:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    66d6:	48 89 c7             	mov    rdi,rax
    66d9:	e8 22 b1 ff ff       	call   1800 <BN_CTX_start@plt>
    66de:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    66e2:	0f b6 00             	movzx  eax,BYTE PTR [rax]
    66e5:	84 c0                	test   al,al
    66e7:	74 07                	je     66f0 <secp256k1_algebra_add_points+0xe1>
    66e9:	bf 21 00 00 00       	mov    edi,0x21
    66ee:	eb 05                	jmp    66f5 <secp256k1_algebra_add_points+0xe6>
    66f0:	bf 01 00 00 00       	mov    edi,0x1
    66f5:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    66f9:	48 8b 00             	mov    rax,QWORD PTR [rax]
    66fc:	48 8b 4d e8          	mov    rcx,QWORD PTR [rbp-0x18]
    6700:	48 8b 55 c8          	mov    rdx,QWORD PTR [rbp-0x38]
    6704:	48 8b 75 f0          	mov    rsi,QWORD PTR [rbp-0x10]
    6708:	49 89 c8             	mov    r8,rcx
    670b:	48 89 f9             	mov    rcx,rdi
    670e:	48 89 c7             	mov    rdi,rax
    6711:	e8 2a b0 ff ff       	call   1740 <EC_POINT_oct2point@plt>
    6716:	85 c0                	test   eax,eax
    6718:	75 15                	jne    672f <secp256k1_algebra_add_points+0x120>
    671a:	e8 81 ad ff ff       	call   14a0 <ERR_get_error@plt>
    671f:	48 89 c7             	mov    rdi,rax
    6722:	e8 9f f4 ff ff       	call   5bc6 <from_openssl_error>
    6727:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
    672a:	e9 c8 00 00 00       	jmp    67f7 <secp256k1_algebra_add_points+0x1e8>
    672f:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
    6733:	0f b6 00             	movzx  eax,BYTE PTR [rax]
    6736:	84 c0                	test   al,al
    6738:	74 07                	je     6741 <secp256k1_algebra_add_points+0x132>
    673a:	bf 21 00 00 00       	mov    edi,0x21
    673f:	eb 05                	jmp    6746 <secp256k1_algebra_add_points+0x137>
    6741:	bf 01 00 00 00       	mov    edi,0x1
    6746:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    674a:	48 8b 00             	mov    rax,QWORD PTR [rax]
    674d:	48 8b 4d e8          	mov    rcx,QWORD PTR [rbp-0x18]
    6751:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
    6755:	48 8b 75 f8          	mov    rsi,QWORD PTR [rbp-0x8]
    6759:	49 89 c8             	mov    r8,rcx
    675c:	48 89 f9             	mov    rcx,rdi
    675f:	48 89 c7             	mov    rdi,rax
    6762:	e8 d9 af ff ff       	call   1740 <EC_POINT_oct2point@plt>
    6767:	85 c0                	test   eax,eax
    6769:	75 12                	jne    677d <secp256k1_algebra_add_points+0x16e>
    676b:	e8 30 ad ff ff       	call   14a0 <ERR_get_error@plt>
    6770:	48 89 c7             	mov    rdi,rax
    6773:	e8 4e f4 ff ff       	call   5bc6 <from_openssl_error>
    6778:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
    677b:	eb 7a                	jmp    67f7 <secp256k1_algebra_add_points+0x1e8>
    677d:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    6781:	48 8b 00             	mov    rax,QWORD PTR [rax]
    6784:	48 8b 7d e8          	mov    rdi,QWORD PTR [rbp-0x18]
    6788:	48 8b 4d f8          	mov    rcx,QWORD PTR [rbp-0x8]
    678c:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
    6790:	48 8b 75 f0          	mov    rsi,QWORD PTR [rbp-0x10]
    6794:	49 89 f8             	mov    r8,rdi
    6797:	48 89 c7             	mov    rdi,rax
    679a:	e8 41 b0 ff ff       	call   17e0 <EC_POINT_add@plt>
    679f:	85 c0                	test   eax,eax
    67a1:	74 50                	je     67f3 <secp256k1_algebra_add_points+0x1e4>
    67a3:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
    67a7:	ba 21 00 00 00       	mov    edx,0x21
    67ac:	be 00 00 00 00       	mov    esi,0x0
    67b1:	48 89 c7             	mov    rdi,rax
    67b4:	e8 d7 ac ff ff       	call   1490 <memset@plt>
    67b9:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    67bd:	48 8b 00             	mov    rax,QWORD PTR [rax]
    67c0:	48 8b 4d e8          	mov    rcx,QWORD PTR [rbp-0x18]
    67c4:	48 8b 55 d0          	mov    rdx,QWORD PTR [rbp-0x30]
    67c8:	48 8b 75 f0          	mov    rsi,QWORD PTR [rbp-0x10]
    67cc:	49 89 c9             	mov    r9,rcx
    67cf:	41 b8 21 00 00 00    	mov    r8d,0x21
    67d5:	48 89 d1             	mov    rcx,rdx
    67d8:	ba 02 00 00 00       	mov    edx,0x2
    67dd:	48 89 c7             	mov    rdi,rax
    67e0:	e8 4b ae ff ff       	call   1630 <EC_POINT_point2oct@plt>
    67e5:	48 85 c0             	test   rax,rax
    67e8:	74 0c                	je     67f6 <secp256k1_algebra_add_points+0x1e7>
    67ea:	c7 45 e4 00 00 00 00 	mov    DWORD PTR [rbp-0x1c],0x0
    67f1:	eb 04                	jmp    67f7 <secp256k1_algebra_add_points+0x1e8>
    67f3:	90                   	nop
    67f4:	eb 01                	jmp    67f7 <secp256k1_algebra_add_points+0x1e8>
    67f6:	90                   	nop
    67f7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    67fb:	48 89 c7             	mov    rdi,rax
    67fe:	e8 cd af ff ff       	call   17d0 <BN_CTX_end@plt>
    6803:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    6807:	48 89 c7             	mov    rdi,rax
    680a:	e8 c1 ac ff ff       	call   14d0 <BN_CTX_free@plt>
    680f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    6813:	48 89 c7             	mov    rdi,rax
    6816:	e8 35 af ff ff       	call   1750 <EC_POINT_free@plt>
    681b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    681f:	48 89 c7             	mov    rdi,rax
    6822:	e8 29 af ff ff       	call   1750 <EC_POINT_free@plt>
    6827:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
    682a:	c9                   	leave  
    682b:	c3                   	ret    

000000000000682c <secp256k1_algebra_point_mul>:
    682c:	55                   	push   rbp
    682d:	48 89 e5             	mov    rbp,rsp
    6830:	48 83 ec 40          	sub    rsp,0x40
    6834:	48 89 7d d8          	mov    QWORD PTR [rbp-0x28],rdi
    6838:	48 89 75 d0          	mov    QWORD PTR [rbp-0x30],rsi
    683c:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
    6840:	48 89 4d c0          	mov    QWORD PTR [rbp-0x40],rcx
    6844:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
    684b:	00 
    684c:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
    6853:	00 
    6854:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
    685b:	00 
    685c:	c7 45 e4 ff ff ff ff 	mov    DWORD PTR [rbp-0x1c],0xffffffff
    6863:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
    6868:	74 15                	je     687f <secp256k1_algebra_point_mul+0x53>
    686a:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
    686f:	74 0e                	je     687f <secp256k1_algebra_point_mul+0x53>
    6871:	48 83 7d c8 00       	cmp    QWORD PTR [rbp-0x38],0x0
    6876:	74 07                	je     687f <secp256k1_algebra_point_mul+0x53>
    6878:	48 83 7d c0 00       	cmp    QWORD PTR [rbp-0x40],0x0
    687d:	75 0a                	jne    6889 <secp256k1_algebra_point_mul+0x5d>
    687f:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    6884:	e9 99 01 00 00       	jmp    6a22 <secp256k1_algebra_point_mul+0x1f6>
    6889:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    688d:	48 8b 00             	mov    rax,QWORD PTR [rax]
    6890:	48 89 c7             	mov    rdi,rax
    6893:	e8 08 ad ff ff       	call   15a0 <EC_POINT_new@plt>
    6898:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    689c:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    68a1:	75 0a                	jne    68ad <secp256k1_algebra_point_mul+0x81>
    68a3:	b8 fc ff ff ff       	mov    eax,0xfffffffc
    68a8:	e9 75 01 00 00       	jmp    6a22 <secp256k1_algebra_point_mul+0x1f6>
    68ad:	e8 1e ae ff ff       	call   16d0 <BN_CTX_new@plt>
    68b2:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
    68b6:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
    68bb:	75 0c                	jne    68c9 <secp256k1_algebra_point_mul+0x9d>
    68bd:	c7 45 e4 fc ff ff ff 	mov    DWORD PTR [rbp-0x1c],0xfffffffc
    68c4:	e9 1f 01 00 00       	jmp    69e8 <secp256k1_algebra_point_mul+0x1bc>
    68c9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    68cd:	48 89 c7             	mov    rdi,rax
    68d0:	e8 2b af ff ff       	call   1800 <BN_CTX_start@plt>
    68d5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    68d9:	48 89 c7             	mov    rdi,rax
    68dc:	e8 8f ae ff ff       	call   1770 <BN_CTX_get@plt>
    68e1:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
    68e5:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
    68ea:	74 1a                	je     6906 <secp256k1_algebra_point_mul+0xda>
    68ec:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
    68f0:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
    68f4:	be 20 00 00 00       	mov    esi,0x20
    68f9:	48 89 c7             	mov    rdi,rax
    68fc:	e8 7f ac ff ff       	call   1580 <BN_bin2bn@plt>
    6901:	48 85 c0             	test   rax,rax
    6904:	75 0c                	jne    6912 <secp256k1_algebra_point_mul+0xe6>
    6906:	c7 45 e4 fc ff ff ff 	mov    DWORD PTR [rbp-0x1c],0xfffffffc
    690d:	e9 d6 00 00 00       	jmp    69e8 <secp256k1_algebra_point_mul+0x1bc>
    6912:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    6916:	0f b6 00             	movzx  eax,BYTE PTR [rax]
    6919:	84 c0                	test   al,al
    691b:	74 07                	je     6924 <secp256k1_algebra_point_mul+0xf8>
    691d:	bf 21 00 00 00       	mov    edi,0x21
    6922:	eb 05                	jmp    6929 <secp256k1_algebra_point_mul+0xfd>
    6924:	bf 01 00 00 00       	mov    edi,0x1
    6929:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    692d:	48 8b 00             	mov    rax,QWORD PTR [rax]
    6930:	48 8b 4d f0          	mov    rcx,QWORD PTR [rbp-0x10]
    6934:	48 8b 55 c8          	mov    rdx,QWORD PTR [rbp-0x38]
    6938:	48 8b 75 f8          	mov    rsi,QWORD PTR [rbp-0x8]
    693c:	49 89 c8             	mov    r8,rcx
    693f:	48 89 f9             	mov    rcx,rdi
    6942:	48 89 c7             	mov    rdi,rax
    6945:	e8 f6 ad ff ff       	call   1740 <EC_POINT_oct2point@plt>
    694a:	85 c0                	test   eax,eax
    694c:	75 15                	jne    6963 <secp256k1_algebra_point_mul+0x137>
    694e:	e8 4d ab ff ff       	call   14a0 <ERR_get_error@plt>
    6953:	48 89 c7             	mov    rdi,rax
    6956:	e8 6b f2 ff ff       	call   5bc6 <from_openssl_error>
    695b:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
    695e:	e9 85 00 00 00       	jmp    69e8 <secp256k1_algebra_point_mul+0x1bc>
    6963:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    6967:	48 8b 00             	mov    rax,QWORD PTR [rax]
    696a:	48 8b 7d f0          	mov    rdi,QWORD PTR [rbp-0x10]
    696e:	48 8b 4d e8          	mov    rcx,QWORD PTR [rbp-0x18]
    6972:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
    6976:	48 8b 75 f8          	mov    rsi,QWORD PTR [rbp-0x8]
    697a:	49 89 f9             	mov    r9,rdi
    697d:	49 89 c8             	mov    r8,rcx
    6980:	48 89 d1             	mov    rcx,rdx
    6983:	ba 00 00 00 00       	mov    edx,0x0
    6988:	48 89 c7             	mov    rdi,rax
    698b:	e8 50 ad ff ff       	call   16e0 <EC_POINT_mul@plt>
    6990:	85 c0                	test   eax,eax
    6992:	74 50                	je     69e4 <secp256k1_algebra_point_mul+0x1b8>
    6994:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
    6998:	ba 21 00 00 00       	mov    edx,0x21
    699d:	be 00 00 00 00       	mov    esi,0x0
    69a2:	48 89 c7             	mov    rdi,rax
    69a5:	e8 e6 aa ff ff       	call   1490 <memset@plt>
    69aa:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    69ae:	48 8b 00             	mov    rax,QWORD PTR [rax]
    69b1:	48 8b 4d f0          	mov    rcx,QWORD PTR [rbp-0x10]
    69b5:	48 8b 55 d0          	mov    rdx,QWORD PTR [rbp-0x30]
    69b9:	48 8b 75 f8          	mov    rsi,QWORD PTR [rbp-0x8]
    69bd:	49 89 c9             	mov    r9,rcx
    69c0:	41 b8 21 00 00 00    	mov    r8d,0x21
    69c6:	48 89 d1             	mov    rcx,rdx
    69c9:	ba 02 00 00 00       	mov    edx,0x2
    69ce:	48 89 c7             	mov    rdi,rax
    69d1:	e8 5a ac ff ff       	call   1630 <EC_POINT_point2oct@plt>
    69d6:	48 85 c0             	test   rax,rax
    69d9:	74 0c                	je     69e7 <secp256k1_algebra_point_mul+0x1bb>
    69db:	c7 45 e4 00 00 00 00 	mov    DWORD PTR [rbp-0x1c],0x0
    69e2:	eb 04                	jmp    69e8 <secp256k1_algebra_point_mul+0x1bc>
    69e4:	90                   	nop
    69e5:	eb 01                	jmp    69e8 <secp256k1_algebra_point_mul+0x1bc>
    69e7:	90                   	nop
    69e8:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
    69ed:	74 0c                	je     69fb <secp256k1_algebra_point_mul+0x1cf>
    69ef:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    69f3:	48 89 c7             	mov    rdi,rax
    69f6:	e8 75 ac ff ff       	call   1670 <BN_clear@plt>
    69fb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    69ff:	48 89 c7             	mov    rdi,rax
    6a02:	e8 c9 ad ff ff       	call   17d0 <BN_CTX_end@plt>
    6a07:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    6a0b:	48 89 c7             	mov    rdi,rax
    6a0e:	e8 bd aa ff ff       	call   14d0 <BN_CTX_free@plt>
    6a13:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    6a17:	48 89 c7             	mov    rdi,rax
    6a1a:	e8 31 ad ff ff       	call   1750 <EC_POINT_free@plt>
    6a1f:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
    6a22:	c9                   	leave  
    6a23:	c3                   	ret    

0000000000006a24 <secp256k1_algebra_get_point_projection>:
    6a24:	55                   	push   rbp
    6a25:	48 89 e5             	mov    rbp,rsp
    6a28:	48 83 ec 40          	sub    rsp,0x40
    6a2c:	48 89 7d d8          	mov    QWORD PTR [rbp-0x28],rdi
    6a30:	48 89 75 d0          	mov    QWORD PTR [rbp-0x30],rsi
    6a34:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
    6a38:	48 89 4d c0          	mov    QWORD PTR [rbp-0x40],rcx
    6a3c:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
    6a43:	00 
    6a44:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
    6a4b:	00 
    6a4c:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
    6a53:	00 
    6a54:	c7 45 e4 ff ff ff ff 	mov    DWORD PTR [rbp-0x1c],0xffffffff
    6a5b:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
    6a60:	74 0e                	je     6a70 <secp256k1_algebra_get_point_projection+0x4c>
    6a62:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
    6a67:	74 07                	je     6a70 <secp256k1_algebra_get_point_projection+0x4c>
    6a69:	48 83 7d c8 00       	cmp    QWORD PTR [rbp-0x38],0x0
    6a6e:	75 0a                	jne    6a7a <secp256k1_algebra_get_point_projection+0x56>
    6a70:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    6a75:	e9 be 01 00 00       	jmp    6c38 <secp256k1_algebra_get_point_projection+0x214>
    6a7a:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
    6a7e:	ba 20 00 00 00       	mov    edx,0x20
    6a83:	be 00 00 00 00       	mov    esi,0x0
    6a88:	48 89 c7             	mov    rdi,rax
    6a8b:	e8 00 aa ff ff       	call   1490 <memset@plt>
    6a90:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    6a94:	48 8b 00             	mov    rax,QWORD PTR [rax]
    6a97:	48 89 c7             	mov    rdi,rax
    6a9a:	e8 01 ab ff ff       	call   15a0 <EC_POINT_new@plt>
    6a9f:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
    6aa3:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
    6aa8:	75 0a                	jne    6ab4 <secp256k1_algebra_get_point_projection+0x90>
    6aaa:	b8 fc ff ff ff       	mov    eax,0xfffffffc
    6aaf:	e9 84 01 00 00       	jmp    6c38 <secp256k1_algebra_get_point_projection+0x214>
    6ab4:	e8 17 ac ff ff       	call   16d0 <BN_CTX_new@plt>
    6ab9:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
    6abd:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
    6ac2:	75 0c                	jne    6ad0 <secp256k1_algebra_get_point_projection+0xac>
    6ac4:	c7 45 e4 fc ff ff ff 	mov    DWORD PTR [rbp-0x1c],0xfffffffc
    6acb:	e9 41 01 00 00       	jmp    6c11 <secp256k1_algebra_get_point_projection+0x1ed>
    6ad0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    6ad4:	48 89 c7             	mov    rdi,rax
    6ad7:	e8 24 ad ff ff       	call   1800 <BN_CTX_start@plt>
    6adc:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    6ae0:	48 89 c7             	mov    rdi,rax
    6ae3:	e8 88 ac ff ff       	call   1770 <BN_CTX_get@plt>
    6ae8:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    6aec:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    6af1:	75 0c                	jne    6aff <secp256k1_algebra_get_point_projection+0xdb>
    6af3:	c7 45 e4 fc ff ff ff 	mov    DWORD PTR [rbp-0x1c],0xfffffffc
    6afa:	e9 12 01 00 00       	jmp    6c11 <secp256k1_algebra_get_point_projection+0x1ed>
    6aff:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    6b03:	0f b6 00             	movzx  eax,BYTE PTR [rax]
    6b06:	84 c0                	test   al,al
    6b08:	74 07                	je     6b11 <secp256k1_algebra_get_point_projection+0xed>
    6b0a:	bf 21 00 00 00       	mov    edi,0x21
    6b0f:	eb 05                	jmp    6b16 <secp256k1_algebra_get_point_projection+0xf2>
    6b11:	bf 01 00 00 00       	mov    edi,0x1
    6b16:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    6b1a:	48 8b 00             	mov    rax,QWORD PTR [rax]
    6b1d:	48 8b 4d e8          	mov    rcx,QWORD PTR [rbp-0x18]
    6b21:	48 8b 55 c8          	mov    rdx,QWORD PTR [rbp-0x38]
    6b25:	48 8b 75 f0          	mov    rsi,QWORD PTR [rbp-0x10]
    6b29:	49 89 c8             	mov    r8,rcx
    6b2c:	48 89 f9             	mov    rcx,rdi
    6b2f:	48 89 c7             	mov    rdi,rax
    6b32:	e8 09 ac ff ff       	call   1740 <EC_POINT_oct2point@plt>
    6b37:	85 c0                	test   eax,eax
    6b39:	75 15                	jne    6b50 <secp256k1_algebra_get_point_projection+0x12c>
    6b3b:	e8 60 a9 ff ff       	call   14a0 <ERR_get_error@plt>
    6b40:	48 89 c7             	mov    rdi,rax
    6b43:	e8 7e f0 ff ff       	call   5bc6 <from_openssl_error>
    6b48:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
    6b4b:	e9 c1 00 00 00       	jmp    6c11 <secp256k1_algebra_get_point_projection+0x1ed>
    6b50:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    6b54:	48 8b 00             	mov    rax,QWORD PTR [rax]
    6b57:	48 8b 4d e8          	mov    rcx,QWORD PTR [rbp-0x18]
    6b5b:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
    6b5f:	48 8b 75 f0          	mov    rsi,QWORD PTR [rbp-0x10]
    6b63:	49 89 c8             	mov    r8,rcx
    6b66:	b9 00 00 00 00       	mov    ecx,0x0
    6b6b:	48 89 c7             	mov    rdi,rax
    6b6e:	e8 dd aa ff ff       	call   1650 <EC_POINT_get_affine_coordinates_GFp@plt>
    6b73:	85 c0                	test   eax,eax
    6b75:	0f 84 92 00 00 00    	je     6c0d <secp256k1_algebra_get_point_projection+0x1e9>
    6b7b:	48 83 7d c0 00       	cmp    QWORD PTR [rbp-0x40],0x0
    6b80:	74 2e                	je     6bb0 <secp256k1_algebra_get_point_projection+0x18c>
    6b82:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    6b86:	48 8b 00             	mov    rax,QWORD PTR [rax]
    6b89:	48 89 c7             	mov    rdi,rax
    6b8c:	e8 af a9 ff ff       	call   1540 <EC_GROUP_get0_order@plt>
    6b91:	48 89 c2             	mov    rdx,rax
    6b94:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    6b98:	48 89 d6             	mov    rsi,rdx
    6b9b:	48 89 c7             	mov    rdi,rax
    6b9e:	e8 6d aa ff ff       	call   1610 <BN_cmp@plt>
    6ba3:	f7 d0                	not    eax
    6ba5:	c1 e8 1f             	shr    eax,0x1f
    6ba8:	89 c2                	mov    edx,eax
    6baa:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
    6bae:	88 10                	mov    BYTE PTR [rax],dl
    6bb0:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    6bb4:	48 8b 00             	mov    rax,QWORD PTR [rax]
    6bb7:	48 89 c7             	mov    rdi,rax
    6bba:	e8 81 a9 ff ff       	call   1540 <EC_GROUP_get0_order@plt>
    6bbf:	48 89 c7             	mov    rdi,rax
    6bc2:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
    6bc6:	48 8b 75 f8          	mov    rsi,QWORD PTR [rbp-0x8]
    6bca:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    6bce:	48 89 d1             	mov    rcx,rdx
    6bd1:	48 89 fa             	mov    rdx,rdi
    6bd4:	48 89 c7             	mov    rdi,rax
    6bd7:	e8 94 a8 ff ff       	call   1470 <BN_nnmod@plt>
    6bdc:	85 c0                	test   eax,eax
    6bde:	74 30                	je     6c10 <secp256k1_algebra_get_point_projection+0x1ec>
    6be0:	48 8b 4d d0          	mov    rcx,QWORD PTR [rbp-0x30]
    6be4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    6be8:	ba 20 00 00 00       	mov    edx,0x20
    6bed:	48 89 ce             	mov    rsi,rcx
    6bf0:	48 89 c7             	mov    rdi,rax
    6bf3:	e8 b8 a8 ff ff       	call   14b0 <BN_bn2binpad@plt>
    6bf8:	85 c0                	test   eax,eax
    6bfa:	7e 07                	jle    6c03 <secp256k1_algebra_get_point_projection+0x1df>
    6bfc:	b8 00 00 00 00       	mov    eax,0x0
    6c01:	eb 05                	jmp    6c08 <secp256k1_algebra_get_point_projection+0x1e4>
    6c03:	b8 ff ff ff ff       	mov    eax,0xffffffff
    6c08:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
    6c0b:	eb 04                	jmp    6c11 <secp256k1_algebra_get_point_projection+0x1ed>
    6c0d:	90                   	nop
    6c0e:	eb 01                	jmp    6c11 <secp256k1_algebra_get_point_projection+0x1ed>
    6c10:	90                   	nop
    6c11:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    6c15:	48 89 c7             	mov    rdi,rax
    6c18:	e8 b3 ab ff ff       	call   17d0 <BN_CTX_end@plt>
    6c1d:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    6c21:	48 89 c7             	mov    rdi,rax
    6c24:	e8 a7 a8 ff ff       	call   14d0 <BN_CTX_free@plt>
    6c29:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    6c2d:	48 89 c7             	mov    rdi,rax
    6c30:	e8 1b ab ff ff       	call   1750 <EC_POINT_free@plt>
    6c35:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
    6c38:	c9                   	leave  
    6c39:	c3                   	ret    

0000000000006c3a <secp256k1_algebra_add_scalars>:
    6c3a:	55                   	push   rbp
    6c3b:	48 89 e5             	mov    rbp,rsp
    6c3e:	48 83 ec 50          	sub    rsp,0x50
    6c42:	48 89 7d d8          	mov    QWORD PTR [rbp-0x28],rdi
    6c46:	48 89 75 d0          	mov    QWORD PTR [rbp-0x30],rsi
    6c4a:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
    6c4e:	89 4d c4             	mov    DWORD PTR [rbp-0x3c],ecx
    6c51:	4c 89 45 b8          	mov    QWORD PTR [rbp-0x48],r8
    6c55:	44 89 4d c0          	mov    DWORD PTR [rbp-0x40],r9d
    6c59:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
    6c60:	00 
    6c61:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
    6c68:	00 
    6c69:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
    6c70:	00 
    6c71:	c7 45 e4 fc ff ff ff 	mov    DWORD PTR [rbp-0x1c],0xfffffffc
    6c78:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
    6c7d:	74 21                	je     6ca0 <secp256k1_algebra_add_scalars+0x66>
    6c7f:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
    6c84:	74 1a                	je     6ca0 <secp256k1_algebra_add_scalars+0x66>
    6c86:	48 83 7d c8 00       	cmp    QWORD PTR [rbp-0x38],0x0
    6c8b:	74 13                	je     6ca0 <secp256k1_algebra_add_scalars+0x66>
    6c8d:	83 7d c4 00          	cmp    DWORD PTR [rbp-0x3c],0x0
    6c91:	74 0d                	je     6ca0 <secp256k1_algebra_add_scalars+0x66>
    6c93:	48 83 7d b8 00       	cmp    QWORD PTR [rbp-0x48],0x0
    6c98:	74 06                	je     6ca0 <secp256k1_algebra_add_scalars+0x66>
    6c9a:	83 7d c0 00          	cmp    DWORD PTR [rbp-0x40],0x0
    6c9e:	75 0a                	jne    6caa <secp256k1_algebra_add_scalars+0x70>
    6ca0:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    6ca5:	e9 66 01 00 00       	jmp    6e10 <secp256k1_algebra_add_scalars+0x1d6>
    6caa:	e8 21 aa ff ff       	call   16d0 <BN_CTX_new@plt>
    6caf:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
    6cb3:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
    6cb8:	75 0a                	jne    6cc4 <secp256k1_algebra_add_scalars+0x8a>
    6cba:	b8 fc ff ff ff       	mov    eax,0xfffffffc
    6cbf:	e9 4c 01 00 00       	jmp    6e10 <secp256k1_algebra_add_scalars+0x1d6>
    6cc4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    6cc8:	48 89 c7             	mov    rdi,rax
    6ccb:	e8 30 ab ff ff       	call   1800 <BN_CTX_start@plt>
    6cd0:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    6cd4:	48 89 c7             	mov    rdi,rax
    6cd7:	e8 94 aa ff ff       	call   1770 <BN_CTX_get@plt>
    6cdc:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    6ce0:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    6ce5:	0f 84 e3 00 00 00    	je     6dce <secp256k1_algebra_add_scalars+0x194>
    6ceb:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
    6cee:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
    6cf2:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    6cf6:	89 ce                	mov    esi,ecx
    6cf8:	48 89 c7             	mov    rdi,rax
    6cfb:	e8 80 a8 ff ff       	call   1580 <BN_bin2bn@plt>
    6d00:	48 85 c0             	test   rax,rax
    6d03:	0f 84 c5 00 00 00    	je     6dce <secp256k1_algebra_add_scalars+0x194>
    6d09:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    6d0d:	48 89 c7             	mov    rdi,rax
    6d10:	e8 5b aa ff ff       	call   1770 <BN_CTX_get@plt>
    6d15:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
    6d19:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
    6d1e:	0f 84 aa 00 00 00    	je     6dce <secp256k1_algebra_add_scalars+0x194>
    6d24:	8b 4d c0             	mov    ecx,DWORD PTR [rbp-0x40]
    6d27:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
    6d2b:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
    6d2f:	89 ce                	mov    esi,ecx
    6d31:	48 89 c7             	mov    rdi,rax
    6d34:	e8 47 a8 ff ff       	call   1580 <BN_bin2bn@plt>
    6d39:	48 85 c0             	test   rax,rax
    6d3c:	0f 84 8c 00 00 00    	je     6dce <secp256k1_algebra_add_scalars+0x194>
    6d42:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    6d46:	be 04 00 00 00       	mov    esi,0x4
    6d4b:	48 89 c7             	mov    rdi,rax
    6d4e:	e8 2d a7 ff ff       	call   1480 <BN_set_flags@plt>
    6d53:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    6d57:	be 04 00 00 00       	mov    esi,0x4
    6d5c:	48 89 c7             	mov    rdi,rax
    6d5f:	e8 1c a7 ff ff       	call   1480 <BN_set_flags@plt>
    6d64:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    6d68:	48 8b 00             	mov    rax,QWORD PTR [rax]
    6d6b:	48 89 c7             	mov    rdi,rax
    6d6e:	e8 cd a7 ff ff       	call   1540 <EC_GROUP_get0_order@plt>
    6d73:	48 89 c7             	mov    rdi,rax
    6d76:	48 8b 4d f0          	mov    rcx,QWORD PTR [rbp-0x10]
    6d7a:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
    6d7e:	48 8b 75 f8          	mov    rsi,QWORD PTR [rbp-0x8]
    6d82:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    6d86:	49 89 c8             	mov    r8,rcx
    6d89:	48 89 f9             	mov    rcx,rdi
    6d8c:	48 89 c7             	mov    rdi,rax
    6d8f:	e8 6c a9 ff ff       	call   1700 <BN_mod_add@plt>
    6d94:	85 c0                	test   eax,eax
    6d96:	74 2d                	je     6dc5 <secp256k1_algebra_add_scalars+0x18b>
    6d98:	48 8b 4d d0          	mov    rcx,QWORD PTR [rbp-0x30]
    6d9c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    6da0:	ba 20 00 00 00       	mov    edx,0x20
    6da5:	48 89 ce             	mov    rsi,rcx
    6da8:	48 89 c7             	mov    rdi,rax
    6dab:	e8 00 a7 ff ff       	call   14b0 <BN_bn2binpad@plt>
    6db0:	85 c0                	test   eax,eax
    6db2:	7e 07                	jle    6dbb <secp256k1_algebra_add_scalars+0x181>
    6db4:	b8 00 00 00 00       	mov    eax,0x0
    6db9:	eb 05                	jmp    6dc0 <secp256k1_algebra_add_scalars+0x186>
    6dbb:	b8 ff ff ff ff       	mov    eax,0xffffffff
    6dc0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
    6dc3:	eb 0a                	jmp    6dcf <secp256k1_algebra_add_scalars+0x195>
    6dc5:	c7 45 e4 ff ff ff ff 	mov    DWORD PTR [rbp-0x1c],0xffffffff
    6dcc:	eb 01                	jmp    6dcf <secp256k1_algebra_add_scalars+0x195>
    6dce:	90                   	nop
    6dcf:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    6dd4:	74 0c                	je     6de2 <secp256k1_algebra_add_scalars+0x1a8>
    6dd6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    6dda:	48 89 c7             	mov    rdi,rax
    6ddd:	e8 8e a8 ff ff       	call   1670 <BN_clear@plt>
    6de2:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
    6de7:	74 0c                	je     6df5 <secp256k1_algebra_add_scalars+0x1bb>
    6de9:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    6ded:	48 89 c7             	mov    rdi,rax
    6df0:	e8 7b a8 ff ff       	call   1670 <BN_clear@plt>
    6df5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    6df9:	48 89 c7             	mov    rdi,rax
    6dfc:	e8 cf a9 ff ff       	call   17d0 <BN_CTX_end@plt>
    6e01:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    6e05:	48 89 c7             	mov    rdi,rax
    6e08:	e8 c3 a6 ff ff       	call   14d0 <BN_CTX_free@plt>
    6e0d:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
    6e10:	c9                   	leave  
    6e11:	c3                   	ret    

0000000000006e12 <secp256k1_algebra_sub_scalars>:
    6e12:	55                   	push   rbp
    6e13:	48 89 e5             	mov    rbp,rsp
    6e16:	48 83 ec 50          	sub    rsp,0x50
    6e1a:	48 89 7d d8          	mov    QWORD PTR [rbp-0x28],rdi
    6e1e:	48 89 75 d0          	mov    QWORD PTR [rbp-0x30],rsi
    6e22:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
    6e26:	89 4d c4             	mov    DWORD PTR [rbp-0x3c],ecx
    6e29:	4c 89 45 b8          	mov    QWORD PTR [rbp-0x48],r8
    6e2d:	44 89 4d c0          	mov    DWORD PTR [rbp-0x40],r9d
    6e31:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
    6e38:	00 
    6e39:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
    6e40:	00 
    6e41:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
    6e48:	00 
    6e49:	c7 45 e4 fc ff ff ff 	mov    DWORD PTR [rbp-0x1c],0xfffffffc
    6e50:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
    6e55:	74 21                	je     6e78 <secp256k1_algebra_sub_scalars+0x66>
    6e57:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
    6e5c:	74 1a                	je     6e78 <secp256k1_algebra_sub_scalars+0x66>
    6e5e:	48 83 7d c8 00       	cmp    QWORD PTR [rbp-0x38],0x0
    6e63:	74 13                	je     6e78 <secp256k1_algebra_sub_scalars+0x66>
    6e65:	83 7d c4 00          	cmp    DWORD PTR [rbp-0x3c],0x0
    6e69:	74 0d                	je     6e78 <secp256k1_algebra_sub_scalars+0x66>
    6e6b:	48 83 7d b8 00       	cmp    QWORD PTR [rbp-0x48],0x0
    6e70:	74 06                	je     6e78 <secp256k1_algebra_sub_scalars+0x66>
    6e72:	83 7d c0 00          	cmp    DWORD PTR [rbp-0x40],0x0
    6e76:	75 0a                	jne    6e82 <secp256k1_algebra_sub_scalars+0x70>
    6e78:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    6e7d:	e9 66 01 00 00       	jmp    6fe8 <secp256k1_algebra_sub_scalars+0x1d6>
    6e82:	e8 49 a8 ff ff       	call   16d0 <BN_CTX_new@plt>
    6e87:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
    6e8b:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
    6e90:	75 0a                	jne    6e9c <secp256k1_algebra_sub_scalars+0x8a>
    6e92:	b8 fc ff ff ff       	mov    eax,0xfffffffc
    6e97:	e9 4c 01 00 00       	jmp    6fe8 <secp256k1_algebra_sub_scalars+0x1d6>
    6e9c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    6ea0:	48 89 c7             	mov    rdi,rax
    6ea3:	e8 58 a9 ff ff       	call   1800 <BN_CTX_start@plt>
    6ea8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    6eac:	48 89 c7             	mov    rdi,rax
    6eaf:	e8 bc a8 ff ff       	call   1770 <BN_CTX_get@plt>
    6eb4:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    6eb8:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    6ebd:	0f 84 e3 00 00 00    	je     6fa6 <secp256k1_algebra_sub_scalars+0x194>
    6ec3:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
    6ec6:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
    6eca:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    6ece:	89 ce                	mov    esi,ecx
    6ed0:	48 89 c7             	mov    rdi,rax
    6ed3:	e8 a8 a6 ff ff       	call   1580 <BN_bin2bn@plt>
    6ed8:	48 85 c0             	test   rax,rax
    6edb:	0f 84 c5 00 00 00    	je     6fa6 <secp256k1_algebra_sub_scalars+0x194>
    6ee1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    6ee5:	48 89 c7             	mov    rdi,rax
    6ee8:	e8 83 a8 ff ff       	call   1770 <BN_CTX_get@plt>
    6eed:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
    6ef1:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
    6ef6:	0f 84 aa 00 00 00    	je     6fa6 <secp256k1_algebra_sub_scalars+0x194>
    6efc:	8b 4d c0             	mov    ecx,DWORD PTR [rbp-0x40]
    6eff:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
    6f03:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
    6f07:	89 ce                	mov    esi,ecx
    6f09:	48 89 c7             	mov    rdi,rax
    6f0c:	e8 6f a6 ff ff       	call   1580 <BN_bin2bn@plt>
    6f11:	48 85 c0             	test   rax,rax
    6f14:	0f 84 8c 00 00 00    	je     6fa6 <secp256k1_algebra_sub_scalars+0x194>
    6f1a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    6f1e:	be 04 00 00 00       	mov    esi,0x4
    6f23:	48 89 c7             	mov    rdi,rax
    6f26:	e8 55 a5 ff ff       	call   1480 <BN_set_flags@plt>
    6f2b:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    6f2f:	be 04 00 00 00       	mov    esi,0x4
    6f34:	48 89 c7             	mov    rdi,rax
    6f37:	e8 44 a5 ff ff       	call   1480 <BN_set_flags@plt>
    6f3c:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    6f40:	48 8b 00             	mov    rax,QWORD PTR [rax]
    6f43:	48 89 c7             	mov    rdi,rax
    6f46:	e8 f5 a5 ff ff       	call   1540 <EC_GROUP_get0_order@plt>
    6f4b:	48 89 c7             	mov    rdi,rax
    6f4e:	48 8b 4d f0          	mov    rcx,QWORD PTR [rbp-0x10]
    6f52:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
    6f56:	48 8b 75 f8          	mov    rsi,QWORD PTR [rbp-0x8]
    6f5a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    6f5e:	49 89 c8             	mov    r8,rcx
    6f61:	48 89 f9             	mov    rcx,rdi
    6f64:	48 89 c7             	mov    rdi,rax
    6f67:	e8 64 a6 ff ff       	call   15d0 <BN_mod_sub@plt>
    6f6c:	85 c0                	test   eax,eax
    6f6e:	74 2d                	je     6f9d <secp256k1_algebra_sub_scalars+0x18b>
    6f70:	48 8b 4d d0          	mov    rcx,QWORD PTR [rbp-0x30]
    6f74:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    6f78:	ba 20 00 00 00       	mov    edx,0x20
    6f7d:	48 89 ce             	mov    rsi,rcx
    6f80:	48 89 c7             	mov    rdi,rax
    6f83:	e8 28 a5 ff ff       	call   14b0 <BN_bn2binpad@plt>
    6f88:	85 c0                	test   eax,eax
    6f8a:	7e 07                	jle    6f93 <secp256k1_algebra_sub_scalars+0x181>
    6f8c:	b8 00 00 00 00       	mov    eax,0x0
    6f91:	eb 05                	jmp    6f98 <secp256k1_algebra_sub_scalars+0x186>
    6f93:	b8 ff ff ff ff       	mov    eax,0xffffffff
    6f98:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
    6f9b:	eb 0a                	jmp    6fa7 <secp256k1_algebra_sub_scalars+0x195>
    6f9d:	c7 45 e4 ff ff ff ff 	mov    DWORD PTR [rbp-0x1c],0xffffffff
    6fa4:	eb 01                	jmp    6fa7 <secp256k1_algebra_sub_scalars+0x195>
    6fa6:	90                   	nop
    6fa7:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    6fac:	74 0c                	je     6fba <secp256k1_algebra_sub_scalars+0x1a8>
    6fae:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    6fb2:	48 89 c7             	mov    rdi,rax
    6fb5:	e8 b6 a6 ff ff       	call   1670 <BN_clear@plt>
    6fba:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
    6fbf:	74 0c                	je     6fcd <secp256k1_algebra_sub_scalars+0x1bb>
    6fc1:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    6fc5:	48 89 c7             	mov    rdi,rax
    6fc8:	e8 a3 a6 ff ff       	call   1670 <BN_clear@plt>
    6fcd:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    6fd1:	48 89 c7             	mov    rdi,rax
    6fd4:	e8 f7 a7 ff ff       	call   17d0 <BN_CTX_end@plt>
    6fd9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    6fdd:	48 89 c7             	mov    rdi,rax
    6fe0:	e8 eb a4 ff ff       	call   14d0 <BN_CTX_free@plt>
    6fe5:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
    6fe8:	c9                   	leave  
    6fe9:	c3                   	ret    

0000000000006fea <secp256k1_algebra_mul_scalars>:
    6fea:	55                   	push   rbp
    6feb:	48 89 e5             	mov    rbp,rsp
    6fee:	48 83 ec 50          	sub    rsp,0x50
    6ff2:	48 89 7d d8          	mov    QWORD PTR [rbp-0x28],rdi
    6ff6:	48 89 75 d0          	mov    QWORD PTR [rbp-0x30],rsi
    6ffa:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
    6ffe:	89 4d c4             	mov    DWORD PTR [rbp-0x3c],ecx
    7001:	4c 89 45 b8          	mov    QWORD PTR [rbp-0x48],r8
    7005:	44 89 4d c0          	mov    DWORD PTR [rbp-0x40],r9d
    7009:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
    7010:	00 
    7011:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
    7018:	00 
    7019:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
    7020:	00 
    7021:	c7 45 e4 fc ff ff ff 	mov    DWORD PTR [rbp-0x1c],0xfffffffc
    7028:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
    702d:	74 21                	je     7050 <secp256k1_algebra_mul_scalars+0x66>
    702f:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
    7034:	74 1a                	je     7050 <secp256k1_algebra_mul_scalars+0x66>
    7036:	48 83 7d c8 00       	cmp    QWORD PTR [rbp-0x38],0x0
    703b:	74 13                	je     7050 <secp256k1_algebra_mul_scalars+0x66>
    703d:	83 7d c4 00          	cmp    DWORD PTR [rbp-0x3c],0x0
    7041:	74 0d                	je     7050 <secp256k1_algebra_mul_scalars+0x66>
    7043:	48 83 7d b8 00       	cmp    QWORD PTR [rbp-0x48],0x0
    7048:	74 06                	je     7050 <secp256k1_algebra_mul_scalars+0x66>
    704a:	83 7d c0 00          	cmp    DWORD PTR [rbp-0x40],0x0
    704e:	75 0a                	jne    705a <secp256k1_algebra_mul_scalars+0x70>
    7050:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    7055:	e9 66 01 00 00       	jmp    71c0 <secp256k1_algebra_mul_scalars+0x1d6>
    705a:	e8 71 a6 ff ff       	call   16d0 <BN_CTX_new@plt>
    705f:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
    7063:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
    7068:	75 0a                	jne    7074 <secp256k1_algebra_mul_scalars+0x8a>
    706a:	b8 fc ff ff ff       	mov    eax,0xfffffffc
    706f:	e9 4c 01 00 00       	jmp    71c0 <secp256k1_algebra_mul_scalars+0x1d6>
    7074:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    7078:	48 89 c7             	mov    rdi,rax
    707b:	e8 80 a7 ff ff       	call   1800 <BN_CTX_start@plt>
    7080:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    7084:	48 89 c7             	mov    rdi,rax
    7087:	e8 e4 a6 ff ff       	call   1770 <BN_CTX_get@plt>
    708c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    7090:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    7095:	0f 84 e3 00 00 00    	je     717e <secp256k1_algebra_mul_scalars+0x194>
    709b:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
    709e:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
    70a2:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    70a6:	89 ce                	mov    esi,ecx
    70a8:	48 89 c7             	mov    rdi,rax
    70ab:	e8 d0 a4 ff ff       	call   1580 <BN_bin2bn@plt>
    70b0:	48 85 c0             	test   rax,rax
    70b3:	0f 84 c5 00 00 00    	je     717e <secp256k1_algebra_mul_scalars+0x194>
    70b9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    70bd:	48 89 c7             	mov    rdi,rax
    70c0:	e8 ab a6 ff ff       	call   1770 <BN_CTX_get@plt>
    70c5:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
    70c9:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
    70ce:	0f 84 aa 00 00 00    	je     717e <secp256k1_algebra_mul_scalars+0x194>
    70d4:	8b 4d c0             	mov    ecx,DWORD PTR [rbp-0x40]
    70d7:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
    70db:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
    70df:	89 ce                	mov    esi,ecx
    70e1:	48 89 c7             	mov    rdi,rax
    70e4:	e8 97 a4 ff ff       	call   1580 <BN_bin2bn@plt>
    70e9:	48 85 c0             	test   rax,rax
    70ec:	0f 84 8c 00 00 00    	je     717e <secp256k1_algebra_mul_scalars+0x194>
    70f2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    70f6:	be 04 00 00 00       	mov    esi,0x4
    70fb:	48 89 c7             	mov    rdi,rax
    70fe:	e8 7d a3 ff ff       	call   1480 <BN_set_flags@plt>
    7103:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    7107:	be 04 00 00 00       	mov    esi,0x4
    710c:	48 89 c7             	mov    rdi,rax
    710f:	e8 6c a3 ff ff       	call   1480 <BN_set_flags@plt>
    7114:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    7118:	48 8b 00             	mov    rax,QWORD PTR [rax]
    711b:	48 89 c7             	mov    rdi,rax
    711e:	e8 1d a4 ff ff       	call   1540 <EC_GROUP_get0_order@plt>
    7123:	48 89 c7             	mov    rdi,rax
    7126:	48 8b 4d f0          	mov    rcx,QWORD PTR [rbp-0x10]
    712a:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
    712e:	48 8b 75 f8          	mov    rsi,QWORD PTR [rbp-0x8]
    7132:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    7136:	49 89 c8             	mov    r8,rcx
    7139:	48 89 f9             	mov    rcx,rdi
    713c:	48 89 c7             	mov    rdi,rax
    713f:	e8 7c a3 ff ff       	call   14c0 <BN_mod_mul@plt>
    7144:	85 c0                	test   eax,eax
    7146:	74 2d                	je     7175 <secp256k1_algebra_mul_scalars+0x18b>
    7148:	48 8b 4d d0          	mov    rcx,QWORD PTR [rbp-0x30]
    714c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    7150:	ba 20 00 00 00       	mov    edx,0x20
    7155:	48 89 ce             	mov    rsi,rcx
    7158:	48 89 c7             	mov    rdi,rax
    715b:	e8 50 a3 ff ff       	call   14b0 <BN_bn2binpad@plt>
    7160:	85 c0                	test   eax,eax
    7162:	7e 07                	jle    716b <secp256k1_algebra_mul_scalars+0x181>
    7164:	b8 00 00 00 00       	mov    eax,0x0
    7169:	eb 05                	jmp    7170 <secp256k1_algebra_mul_scalars+0x186>
    716b:	b8 ff ff ff ff       	mov    eax,0xffffffff
    7170:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
    7173:	eb 0a                	jmp    717f <secp256k1_algebra_mul_scalars+0x195>
    7175:	c7 45 e4 ff ff ff ff 	mov    DWORD PTR [rbp-0x1c],0xffffffff
    717c:	eb 01                	jmp    717f <secp256k1_algebra_mul_scalars+0x195>
    717e:	90                   	nop
    717f:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    7184:	74 0c                	je     7192 <secp256k1_algebra_mul_scalars+0x1a8>
    7186:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    718a:	48 89 c7             	mov    rdi,rax
    718d:	e8 de a4 ff ff       	call   1670 <BN_clear@plt>
    7192:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
    7197:	74 0c                	je     71a5 <secp256k1_algebra_mul_scalars+0x1bb>
    7199:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    719d:	48 89 c7             	mov    rdi,rax
    71a0:	e8 cb a4 ff ff       	call   1670 <BN_clear@plt>
    71a5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    71a9:	48 89 c7             	mov    rdi,rax
    71ac:	e8 1f a6 ff ff       	call   17d0 <BN_CTX_end@plt>
    71b1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    71b5:	48 89 c7             	mov    rdi,rax
    71b8:	e8 13 a3 ff ff       	call   14d0 <BN_CTX_free@plt>
    71bd:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
    71c0:	c9                   	leave  
    71c1:	c3                   	ret    

00000000000071c2 <secp256k1_algebra_inverse>:
    71c2:	55                   	push   rbp
    71c3:	48 89 e5             	mov    rbp,rsp
    71c6:	48 83 ec 40          	sub    rsp,0x40
    71ca:	48 89 7d d8          	mov    QWORD PTR [rbp-0x28],rdi
    71ce:	48 89 75 d0          	mov    QWORD PTR [rbp-0x30],rsi
    71d2:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
    71d6:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
    71dd:	00 
    71de:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
    71e5:	00 
    71e6:	c7 45 ec fc ff ff ff 	mov    DWORD PTR [rbp-0x14],0xfffffffc
    71ed:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
    71f2:	74 0e                	je     7202 <secp256k1_algebra_inverse+0x40>
    71f4:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
    71f9:	74 07                	je     7202 <secp256k1_algebra_inverse+0x40>
    71fb:	48 83 7d c8 00       	cmp    QWORD PTR [rbp-0x38],0x0
    7200:	75 0a                	jne    720c <secp256k1_algebra_inverse+0x4a>
    7202:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    7207:	e9 02 01 00 00       	jmp    730e <secp256k1_algebra_inverse+0x14c>
    720c:	e8 bf a4 ff ff       	call   16d0 <BN_CTX_new@plt>
    7211:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
    7215:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
    721a:	75 0a                	jne    7226 <secp256k1_algebra_inverse+0x64>
    721c:	b8 fc ff ff ff       	mov    eax,0xfffffffc
    7221:	e9 e8 00 00 00       	jmp    730e <secp256k1_algebra_inverse+0x14c>
    7226:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    722a:	48 89 c7             	mov    rdi,rax
    722d:	e8 ce a5 ff ff       	call   1800 <BN_CTX_start@plt>
    7232:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    7236:	48 89 c7             	mov    rdi,rax
    7239:	e8 32 a5 ff ff       	call   1770 <BN_CTX_get@plt>
    723e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    7242:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    7247:	0f 84 92 00 00 00    	je     72df <secp256k1_algebra_inverse+0x11d>
    724d:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
    7251:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    7255:	be 20 00 00 00       	mov    esi,0x20
    725a:	48 89 c7             	mov    rdi,rax
    725d:	e8 1e a3 ff ff       	call   1580 <BN_bin2bn@plt>
    7262:	48 85 c0             	test   rax,rax
    7265:	74 78                	je     72df <secp256k1_algebra_inverse+0x11d>
    7267:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    726b:	be 04 00 00 00       	mov    esi,0x4
    7270:	48 89 c7             	mov    rdi,rax
    7273:	e8 08 a2 ff ff       	call   1480 <BN_set_flags@plt>
    7278:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    727c:	48 8b 00             	mov    rax,QWORD PTR [rax]
    727f:	48 89 c7             	mov    rdi,rax
    7282:	e8 b9 a2 ff ff       	call   1540 <EC_GROUP_get0_order@plt>
    7287:	48 89 c7             	mov    rdi,rax
    728a:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
    728e:	48 8b 75 f8          	mov    rsi,QWORD PTR [rbp-0x8]
    7292:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    7296:	48 89 d1             	mov    rcx,rdx
    7299:	48 89 fa             	mov    rdx,rdi
    729c:	48 89 c7             	mov    rdi,rax
    729f:	e8 3c a2 ff ff       	call   14e0 <BN_mod_inverse@plt>
    72a4:	48 85 c0             	test   rax,rax
    72a7:	74 2d                	je     72d6 <secp256k1_algebra_inverse+0x114>
    72a9:	48 8b 4d d0          	mov    rcx,QWORD PTR [rbp-0x30]
    72ad:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    72b1:	ba 20 00 00 00       	mov    edx,0x20
    72b6:	48 89 ce             	mov    rsi,rcx
    72b9:	48 89 c7             	mov    rdi,rax
    72bc:	e8 ef a1 ff ff       	call   14b0 <BN_bn2binpad@plt>
    72c1:	85 c0                	test   eax,eax
    72c3:	7e 07                	jle    72cc <secp256k1_algebra_inverse+0x10a>
    72c5:	b8 00 00 00 00       	mov    eax,0x0
    72ca:	eb 05                	jmp    72d1 <secp256k1_algebra_inverse+0x10f>
    72cc:	b8 ff ff ff ff       	mov    eax,0xffffffff
    72d1:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
    72d4:	eb 0a                	jmp    72e0 <secp256k1_algebra_inverse+0x11e>
    72d6:	c7 45 ec ff ff ff ff 	mov    DWORD PTR [rbp-0x14],0xffffffff
    72dd:	eb 01                	jmp    72e0 <secp256k1_algebra_inverse+0x11e>
    72df:	90                   	nop
    72e0:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    72e5:	74 0c                	je     72f3 <secp256k1_algebra_inverse+0x131>
    72e7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    72eb:	48 89 c7             	mov    rdi,rax
    72ee:	e8 7d a3 ff ff       	call   1670 <BN_clear@plt>
    72f3:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    72f7:	48 89 c7             	mov    rdi,rax
    72fa:	e8 d1 a4 ff ff       	call   17d0 <BN_CTX_end@plt>
    72ff:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    7303:	48 89 c7             	mov    rdi,rax
    7306:	e8 c5 a1 ff ff       	call   14d0 <BN_CTX_free@plt>
    730b:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
    730e:	c9                   	leave  
    730f:	c3                   	ret    

0000000000007310 <secp256k1_algebra_abs>:
    7310:	55                   	push   rbp
    7311:	48 89 e5             	mov    rbp,rsp
    7314:	48 83 ec 50          	sub    rsp,0x50
    7318:	48 89 7d c8          	mov    QWORD PTR [rbp-0x38],rdi
    731c:	48 89 75 c0          	mov    QWORD PTR [rbp-0x40],rsi
    7320:	48 89 55 b8          	mov    QWORD PTR [rbp-0x48],rdx
    7324:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
    732b:	00 
    732c:	48 c7 45 e0 00 00 00 	mov    QWORD PTR [rbp-0x20],0x0
    7333:	00 
    7334:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
    733b:	00 
    733c:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
    7343:	00 
    7344:	c7 45 dc fc ff ff ff 	mov    DWORD PTR [rbp-0x24],0xfffffffc
    734b:	48 83 7d c8 00       	cmp    QWORD PTR [rbp-0x38],0x0
    7350:	74 0e                	je     7360 <secp256k1_algebra_abs+0x50>
    7352:	48 83 7d c0 00       	cmp    QWORD PTR [rbp-0x40],0x0
    7357:	74 07                	je     7360 <secp256k1_algebra_abs+0x50>
    7359:	48 83 7d b8 00       	cmp    QWORD PTR [rbp-0x48],0x0
    735e:	75 0a                	jne    736a <secp256k1_algebra_abs+0x5a>
    7360:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    7365:	e9 70 01 00 00       	jmp    74da <secp256k1_algebra_abs+0x1ca>
    736a:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    736e:	48 8b 00             	mov    rax,QWORD PTR [rax]
    7371:	48 89 c7             	mov    rdi,rax
    7374:	e8 c7 a1 ff ff       	call   1540 <EC_GROUP_get0_order@plt>
    7379:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    737d:	e8 3e a3 ff ff       	call   16c0 <BN_new@plt>
    7382:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
    7386:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
    738b:	0f 84 09 01 00 00    	je     749a <secp256k1_algebra_abs+0x18a>
    7391:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
    7395:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
    7399:	be 20 00 00 00       	mov    esi,0x20
    739e:	48 89 c7             	mov    rdi,rax
    73a1:	e8 da a1 ff ff       	call   1580 <BN_bin2bn@plt>
    73a6:	48 85 c0             	test   rax,rax
    73a9:	0f 84 eb 00 00 00    	je     749a <secp256k1_algebra_abs+0x18a>
    73af:	e8 0c a3 ff ff       	call   16c0 <BN_new@plt>
    73b4:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
    73b8:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
    73bd:	0f 84 d7 00 00 00    	je     749a <secp256k1_algebra_abs+0x18a>
    73c3:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
    73c7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    73cb:	48 89 d6             	mov    rsi,rdx
    73ce:	48 89 c7             	mov    rdi,rax
    73d1:	e8 ca a3 ff ff       	call   17a0 <BN_rshift1@plt>
    73d6:	85 c0                	test   eax,eax
    73d8:	0f 84 bc 00 00 00    	je     749a <secp256k1_algebra_abs+0x18a>
    73de:	e8 dd a2 ff ff       	call   16c0 <BN_new@plt>
    73e3:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
    73e7:	48 83 7d e0 00       	cmp    QWORD PTR [rbp-0x20],0x0
    73ec:	0f 84 ab 00 00 00    	je     749d <secp256k1_algebra_abs+0x18d>
    73f2:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
    73f6:	48 8b 4d f8          	mov    rcx,QWORD PTR [rbp-0x8]
    73fa:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
    73fe:	48 89 ce             	mov    rsi,rcx
    7401:	48 89 c7             	mov    rdi,rax
    7404:	e8 e7 a1 ff ff       	call   15f0 <BN_sub@plt>
    7409:	85 c0                	test   eax,eax
    740b:	75 0c                	jne    7419 <secp256k1_algebra_abs+0x109>
    740d:	c7 45 dc ff ff ff ff 	mov    DWORD PTR [rbp-0x24],0xffffffff
    7414:	e9 85 00 00 00       	jmp    749e <secp256k1_algebra_abs+0x18e>
    7419:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
    741d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    7421:	48 89 d6             	mov    rsi,rdx
    7424:	48 89 c7             	mov    rdi,rax
    7427:	e8 e4 a1 ff ff       	call   1610 <BN_cmp@plt>
    742c:	85 c0                	test   eax,eax
    742e:	7e 3d                	jle    746d <secp256k1_algebra_abs+0x15d>
    7430:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
    7434:	48 89 c7             	mov    rdi,rax
    7437:	e8 a4 a1 ff ff       	call   15e0 <BN_is_negative@plt>
    743c:	85 c0                	test   eax,eax
    743e:	75 2d                	jne    746d <secp256k1_algebra_abs+0x15d>
    7440:	48 8b 4d c0          	mov    rcx,QWORD PTR [rbp-0x40]
    7444:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
    7448:	ba 20 00 00 00       	mov    edx,0x20
    744d:	48 89 ce             	mov    rsi,rcx
    7450:	48 89 c7             	mov    rdi,rax
    7453:	e8 58 a0 ff ff       	call   14b0 <BN_bn2binpad@plt>
    7458:	85 c0                	test   eax,eax
    745a:	7e 07                	jle    7463 <secp256k1_algebra_abs+0x153>
    745c:	b8 00 00 00 00       	mov    eax,0x0
    7461:	eb 05                	jmp    7468 <secp256k1_algebra_abs+0x158>
    7463:	b8 ff ff ff ff       	mov    eax,0xffffffff
    7468:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
    746b:	eb 31                	jmp    749e <secp256k1_algebra_abs+0x18e>
    746d:	48 8b 4d c0          	mov    rcx,QWORD PTR [rbp-0x40]
    7471:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    7475:	ba 20 00 00 00       	mov    edx,0x20
    747a:	48 89 ce             	mov    rsi,rcx
    747d:	48 89 c7             	mov    rdi,rax
    7480:	e8 2b a0 ff ff       	call   14b0 <BN_bn2binpad@plt>
    7485:	85 c0                	test   eax,eax
    7487:	7e 07                	jle    7490 <secp256k1_algebra_abs+0x180>
    7489:	b8 00 00 00 00       	mov    eax,0x0
    748e:	eb 05                	jmp    7495 <secp256k1_algebra_abs+0x185>
    7490:	b8 ff ff ff ff       	mov    eax,0xffffffff
    7495:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
    7498:	eb 04                	jmp    749e <secp256k1_algebra_abs+0x18e>
    749a:	90                   	nop
    749b:	eb 01                	jmp    749e <secp256k1_algebra_abs+0x18e>
    749d:	90                   	nop
    749e:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
    74a3:	74 0c                	je     74b1 <secp256k1_algebra_abs+0x1a1>
    74a5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    74a9:	48 89 c7             	mov    rdi,rax
    74ac:	e8 8f a1 ff ff       	call   1640 <BN_clear_free@plt>
    74b1:	48 83 7d e0 00       	cmp    QWORD PTR [rbp-0x20],0x0
    74b6:	74 0c                	je     74c4 <secp256k1_algebra_abs+0x1b4>
    74b8:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
    74bc:	48 89 c7             	mov    rdi,rax
    74bf:	e8 7c a1 ff ff       	call   1640 <BN_clear_free@plt>
    74c4:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
    74c9:	74 0c                	je     74d7 <secp256k1_algebra_abs+0x1c7>
    74cb:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    74cf:	48 89 c7             	mov    rdi,rax
    74d2:	e8 49 a3 ff ff       	call   1820 <BN_free@plt>
    74d7:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
    74da:	c9                   	leave  
    74db:	c3                   	ret    

00000000000074dc <secp256k1_algebra_rand>:
    74dc:	55                   	push   rbp
    74dd:	48 89 e5             	mov    rbp,rsp
    74e0:	48 83 ec 20          	sub    rsp,0x20
    74e4:	48 89 7d e8          	mov    QWORD PTR [rbp-0x18],rdi
    74e8:	48 89 75 e0          	mov    QWORD PTR [rbp-0x20],rsi
    74ec:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
    74f3:	00 
    74f4:	c7 45 f4 fc ff ff ff 	mov    DWORD PTR [rbp-0xc],0xfffffffc
    74fb:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
    7500:	74 07                	je     7509 <secp256k1_algebra_rand+0x2d>
    7502:	48 83 7d e0 00       	cmp    QWORD PTR [rbp-0x20],0x0
    7507:	75 07                	jne    7510 <secp256k1_algebra_rand+0x34>
    7509:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    750e:	eb 7b                	jmp    758b <secp256k1_algebra_rand+0xaf>
    7510:	e8 ab a1 ff ff       	call   16c0 <BN_new@plt>
    7515:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    7519:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    751e:	74 5b                	je     757b <secp256k1_algebra_rand+0x9f>
    7520:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    7524:	48 8b 00             	mov    rax,QWORD PTR [rax]
    7527:	48 89 c7             	mov    rdi,rax
    752a:	e8 11 a0 ff ff       	call   1540 <EC_GROUP_get0_order@plt>
    752f:	48 89 c2             	mov    rdx,rax
    7532:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    7536:	48 89 d6             	mov    rsi,rdx
    7539:	48 89 c7             	mov    rdi,rax
    753c:	e8 bf a0 ff ff       	call   1600 <BN_rand_range@plt>
    7541:	85 c0                	test   eax,eax
    7543:	75 09                	jne    754e <secp256k1_algebra_rand+0x72>
    7545:	c7 45 f4 ff ff ff ff 	mov    DWORD PTR [rbp-0xc],0xffffffff
    754c:	eb 2e                	jmp    757c <secp256k1_algebra_rand+0xa0>
    754e:	48 8b 4d e0          	mov    rcx,QWORD PTR [rbp-0x20]
    7552:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    7556:	ba 20 00 00 00       	mov    edx,0x20
    755b:	48 89 ce             	mov    rsi,rcx
    755e:	48 89 c7             	mov    rdi,rax
    7561:	e8 4a 9f ff ff       	call   14b0 <BN_bn2binpad@plt>
    7566:	85 c0                	test   eax,eax
    7568:	7e 07                	jle    7571 <secp256k1_algebra_rand+0x95>
    756a:	b8 00 00 00 00       	mov    eax,0x0
    756f:	eb 05                	jmp    7576 <secp256k1_algebra_rand+0x9a>
    7571:	b8 ff ff ff ff       	mov    eax,0xffffffff
    7576:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
    7579:	eb 01                	jmp    757c <secp256k1_algebra_rand+0xa0>
    757b:	90                   	nop
    757c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    7580:	48 89 c7             	mov    rdi,rax
    7583:	e8 b8 a0 ff ff       	call   1640 <BN_clear_free@plt>
    7588:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
    758b:	c9                   	leave  
    758c:	c3                   	ret    

000000000000758d <commitments_create_commitment_for_data>:
    758d:	55                   	push   rbp
    758e:	48 89 e5             	mov    rbp,rsp
    7591:	48 81 ec a0 00 00 00 	sub    rsp,0xa0
    7598:	48 89 bd 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdi
    759f:	89 b5 74 ff ff ff    	mov    DWORD PTR [rbp-0x8c],esi
    75a5:	48 89 95 68 ff ff ff 	mov    QWORD PTR [rbp-0x98],rdx
    75ac:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    75b3:	00 00 
    75b5:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    75b9:	31 c0                	xor    eax,eax
    75bb:	48 83 bd 78 ff ff ff 	cmp    QWORD PTR [rbp-0x88],0x0
    75c2:	00 
    75c3:	74 13                	je     75d8 <commitments_create_commitment_for_data+0x4b>
    75c5:	83 bd 74 ff ff ff 00 	cmp    DWORD PTR [rbp-0x8c],0x0
    75cc:	74 0a                	je     75d8 <commitments_create_commitment_for_data+0x4b>
    75ce:	48 83 bd 68 ff ff ff 	cmp    QWORD PTR [rbp-0x98],0x0
    75d5:	00 
    75d6:	75 0a                	jne    75e2 <commitments_create_commitment_for_data+0x55>
    75d8:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    75dd:	e9 81 00 00 00       	jmp    7663 <commitments_create_commitment_for_data+0xd6>
    75e2:	48 8b 85 68 ff ff ff 	mov    rax,QWORD PTR [rbp-0x98]
    75e9:	be 20 00 00 00       	mov    esi,0x20
    75ee:	48 89 c7             	mov    rdi,rax
    75f1:	e8 6a a1 ff ff       	call   1760 <RAND_bytes@plt>
    75f6:	85 c0                	test   eax,eax
    75f8:	75 07                	jne    7601 <commitments_create_commitment_for_data+0x74>
    75fa:	b8 ff ff ff ff       	mov    eax,0xffffffff
    75ff:	eb 62                	jmp    7663 <commitments_create_commitment_for_data+0xd6>
    7601:	48 8d 45 80          	lea    rax,[rbp-0x80]
    7605:	48 89 c7             	mov    rdi,rax
    7608:	e8 a3 a1 ff ff       	call   17b0 <SHA256_Init@plt>
    760d:	48 8b 8d 68 ff ff ff 	mov    rcx,QWORD PTR [rbp-0x98]
    7614:	48 8d 45 80          	lea    rax,[rbp-0x80]
    7618:	ba 20 00 00 00       	mov    edx,0x20
    761d:	48 89 ce             	mov    rsi,rcx
    7620:	48 89 c7             	mov    rdi,rax
    7623:	e8 68 a1 ff ff       	call   1790 <SHA256_Update@plt>
    7628:	8b 95 74 ff ff ff    	mov    edx,DWORD PTR [rbp-0x8c]
    762e:	48 8b 8d 78 ff ff ff 	mov    rcx,QWORD PTR [rbp-0x88]
    7635:	48 8d 45 80          	lea    rax,[rbp-0x80]
    7639:	48 89 ce             	mov    rsi,rcx
    763c:	48 89 c7             	mov    rdi,rax
    763f:	e8 4c a1 ff ff       	call   1790 <SHA256_Update@plt>
    7644:	48 8b 85 68 ff ff ff 	mov    rax,QWORD PTR [rbp-0x98]
    764b:	48 8d 50 20          	lea    rdx,[rax+0x20]
    764f:	48 8d 45 80          	lea    rax,[rbp-0x80]
    7653:	48 89 c6             	mov    rsi,rax
    7656:	48 89 d7             	mov    rdi,rdx
    7659:	e8 02 a0 ff ff       	call   1660 <SHA256_Final@plt>
    765e:	b8 00 00 00 00       	mov    eax,0x0
    7663:	48 8b 4d f8          	mov    rcx,QWORD PTR [rbp-0x8]
    7667:	64 48 33 0c 25 28 00 	xor    rcx,QWORD PTR fs:0x28
    766e:	00 00 
    7670:	74 05                	je     7677 <commitments_create_commitment_for_data+0xea>
    7672:	e8 79 a0 ff ff       	call   16f0 <__stack_chk_fail@plt>
    7677:	c9                   	leave  
    7678:	c3                   	ret    

0000000000007679 <commitments_verify_commitment>:
    7679:	55                   	push   rbp
    767a:	48 89 e5             	mov    rbp,rsp
    767d:	48 81 ec c0 00 00 00 	sub    rsp,0xc0
    7684:	48 89 bd 58 ff ff ff 	mov    QWORD PTR [rbp-0xa8],rdi
    768b:	89 b5 54 ff ff ff    	mov    DWORD PTR [rbp-0xac],esi
    7691:	48 89 95 48 ff ff ff 	mov    QWORD PTR [rbp-0xb8],rdx
    7698:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    769f:	00 00 
    76a1:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    76a5:	31 c0                	xor    eax,eax
    76a7:	48 83 bd 58 ff ff ff 	cmp    QWORD PTR [rbp-0xa8],0x0
    76ae:	00 
    76af:	74 13                	je     76c4 <commitments_verify_commitment+0x4b>
    76b1:	83 bd 54 ff ff ff 00 	cmp    DWORD PTR [rbp-0xac],0x0
    76b8:	74 0a                	je     76c4 <commitments_verify_commitment+0x4b>
    76ba:	48 83 bd 48 ff ff ff 	cmp    QWORD PTR [rbp-0xb8],0x0
    76c1:	00 
    76c2:	75 0a                	jne    76ce <commitments_verify_commitment+0x55>
    76c4:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    76c9:	e9 91 00 00 00       	jmp    775f <commitments_verify_commitment+0xe6>
    76ce:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
    76d5:	48 89 c7             	mov    rdi,rax
    76d8:	e8 d3 a0 ff ff       	call   17b0 <SHA256_Init@plt>
    76dd:	48 8b 8d 48 ff ff ff 	mov    rcx,QWORD PTR [rbp-0xb8]
    76e4:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
    76eb:	ba 20 00 00 00       	mov    edx,0x20
    76f0:	48 89 ce             	mov    rsi,rcx
    76f3:	48 89 c7             	mov    rdi,rax
    76f6:	e8 95 a0 ff ff       	call   1790 <SHA256_Update@plt>
    76fb:	8b 95 54 ff ff ff    	mov    edx,DWORD PTR [rbp-0xac]
    7701:	48 8b 8d 58 ff ff ff 	mov    rcx,QWORD PTR [rbp-0xa8]
    7708:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
    770f:	48 89 ce             	mov    rsi,rcx
    7712:	48 89 c7             	mov    rdi,rax
    7715:	e8 76 a0 ff ff       	call   1790 <SHA256_Update@plt>
    771a:	48 8d 95 60 ff ff ff 	lea    rdx,[rbp-0xa0]
    7721:	48 8d 45 d0          	lea    rax,[rbp-0x30]
    7725:	48 89 d6             	mov    rsi,rdx
    7728:	48 89 c7             	mov    rdi,rax
    772b:	e8 30 9f ff ff       	call   1660 <SHA256_Final@plt>
    7730:	48 8b 85 48 ff ff ff 	mov    rax,QWORD PTR [rbp-0xb8]
    7737:	48 8d 48 20          	lea    rcx,[rax+0x20]
    773b:	48 8d 45 d0          	lea    rax,[rbp-0x30]
    773f:	ba 20 00 00 00       	mov    edx,0x20
    7744:	48 89 ce             	mov    rsi,rcx
    7747:	48 89 c7             	mov    rdi,rax
    774a:	e8 c1 a0 ff ff       	call   1810 <CRYPTO_memcmp@plt>
    774f:	85 c0                	test   eax,eax
    7751:	74 07                	je     775a <commitments_verify_commitment+0xe1>
    7753:	b8 fd ff ff ff       	mov    eax,0xfffffffd
    7758:	eb 05                	jmp    775f <commitments_verify_commitment+0xe6>
    775a:	b8 00 00 00 00       	mov    eax,0x0
    775f:	48 8b 75 f8          	mov    rsi,QWORD PTR [rbp-0x8]
    7763:	64 48 33 34 25 28 00 	xor    rsi,QWORD PTR fs:0x28
    776a:	00 00 
    776c:	74 05                	je     7773 <commitments_verify_commitment+0xfa>
    776e:	e8 7d 9f ff ff       	call   16f0 <__stack_chk_fail@plt>
    7773:	c9                   	leave  
    7774:	c3                   	ret    
    7775:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
    777c:	00 00 00 
    777f:	90                   	nop

0000000000007780 <__libc_csu_init>:
    7780:	41 57                	push   r15
    7782:	41 56                	push   r14
    7784:	49 89 d7             	mov    r15,rdx
    7787:	41 55                	push   r13
    7789:	41 54                	push   r12
    778b:	4c 8d 25 2e 24 20 00 	lea    r12,[rip+0x20242e]        # 209bc0 <__frame_dummy_init_array_entry>
    7792:	55                   	push   rbp
    7793:	48 8d 2d 2e 24 20 00 	lea    rbp,[rip+0x20242e]        # 209bc8 <__init_array_end>
    779a:	53                   	push   rbx
    779b:	41 89 fd             	mov    r13d,edi
    779e:	49 89 f6             	mov    r14,rsi
    77a1:	4c 29 e5             	sub    rbp,r12
    77a4:	48 83 ec 08          	sub    rsp,0x8
    77a8:	48 c1 fd 03          	sar    rbp,0x3
    77ac:	e8 77 9c ff ff       	call   1428 <_init>
    77b1:	48 85 ed             	test   rbp,rbp
    77b4:	74 20                	je     77d6 <__libc_csu_init+0x56>
    77b6:	31 db                	xor    ebx,ebx
    77b8:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
    77bf:	00 
    77c0:	4c 89 fa             	mov    rdx,r15
    77c3:	4c 89 f6             	mov    rsi,r14
    77c6:	44 89 ef             	mov    edi,r13d
    77c9:	41 ff 14 dc          	call   QWORD PTR [r12+rbx*8]
    77cd:	48 83 c3 01          	add    rbx,0x1
    77d1:	48 39 dd             	cmp    rbp,rbx
    77d4:	75 ea                	jne    77c0 <__libc_csu_init+0x40>
    77d6:	48 83 c4 08          	add    rsp,0x8
    77da:	5b                   	pop    rbx
    77db:	5d                   	pop    rbp
    77dc:	41 5c                	pop    r12
    77de:	41 5d                	pop    r13
    77e0:	41 5e                	pop    r14
    77e2:	41 5f                	pop    r15
    77e4:	c3                   	ret    
    77e5:	90                   	nop
    77e6:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
    77ed:	00 00 00 

00000000000077f0 <__libc_csu_fini>:
    77f0:	f3 c3                	repz ret 

Disassembly of section .fini:

00000000000077f4 <_fini>:
    77f4:	48 83 ec 08          	sub    rsp,0x8
    77f8:	48 83 c4 08          	add    rsp,0x8
    77fc:	c3                   	ret    
