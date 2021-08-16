from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime, GCD
from tqdm import tqdm
from pwn import *
from sage.all import *
import gmpy2, pickle, itertools, sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime, subprocess
import numpy as np
import random as rand
import multiprocessing as mp
from base64 import b64encode, b64decode
from sage.modules.free_module_integer import IntegerLattice
from ecdsa import ecdsa
from py_ecc.fields import optimized_bls12_381_FQ12 as FQ12
from py_ecc.optimized_bls12_381 import (
    add,
    curve_order,
    final_exponentiate,
    G1,
    multiply,
    neg,
    pairing,
    Z1,
    Z2,
    G2,
)
from py_ecc.bls.g2_primitives import (
    G1_to_pubkey,
    G2_to_signature,
    pubkey_to_G1,
    signature_to_G2,
    subgroup_check,
    is_inf,
)
from BLS import G2ProofOfPossession as bls

def hasher(x):
    return int(hashlib.sha256(x).hexdigest(), 16)

r = remote('crypto.challenge.bi0s.in', 1337)

wow = [{'Name': 'Nebraska',
  'Vote': 'R',
  'Count': 5,
  'PK': 'aa6fc9c17a1b2de916e5d5453444655e9f6dd3d456b96239f954bc30b80f551c44c1c2423825bc01577e1986098f362b',
  'Sign': 'a09538da373b317adf63cacb53799417ba57d79486aeec78d7687b37e72625190741313800a7698beb2659b725ca728a074514b4cc1fc300dee2e2ae74516993f6760f0839cc4d712a108c58955e062bf45100966fca0288f39f9bfc8ab25706'},
 {'Name': 'Colorado',
  'Vote': 'D',
  'Count': 9,
  'PK': '8205d0b95864290df27875f79fb00f8aba85631de322b29169fb83c871c91baad3d1da9b2484ae6d48438d39d33d4b72',
  'Sign': '839118f1b8492188597f13a4706d3a05851a380c69ca71645934bd02831e916c11463ee5e38bada5087d2c4719b66cb20ba4064c3cd8783f1b2609c1e1ff8a5a050b986120d7266f9c9034cd3e458e49ed378b9400383d7ee3e393396a39ee65'},
 {'Name': 'Louisiana',
  'Vote': 'R',
  'Count': 8,
  'PK': 'a1663af6f40705dacf087e98dc5a3afb140a6bf869369e729c4ea1228d9dec1c216617a0aeb836620497e9d09f267322',
  'Sign': 'b91f2adbf74f101baabdd41815f77296235d5055fbe0c73e05a832d101c1322a780fbc65c12cc6547a3298daf959d1bd119488e646b1717b6061ce272beb996ac19ae92f6e92cfd66bc366a3fbf3173c6a805b725573307434c15d57a2cc55d3'},
 {'Name': 'District of Columbia',
  'Vote': 'D',
  'Count': 3,
  'PK': 'ae098fa365c65473949ddf5c17e6fa7c2806e7eccc28b55830540131e64e9f8b37ac61b34a53d7ec564e46461b33eb59',
  'Sign': 'ac10ca5d32ecff555e7c7691f25bc3b02e53bc8370e256c083e99a197b7bef8cadd1165a26cb944aa1a439e01b9e44321068827ec871a39596dcffdef5e9b2e8d1f0ac927c43cb7f0b31f1898d053810b23aa49b769d5ea733cddffa161b4fef'},
 {'Name': 'North Dakota',
  'Vote': 'R',
  'Count': 3,
  'PK': '87b9293aa4007094c443083009e33a80ea1ff6ea06e5e9056b7ae3e91d5f9702fd91e250e18abcf81369e164998e154c',
  'Sign': '8a4f39d329db4e527d9d02730431977e556787c8ed48806477789074067851e9c0e87c9d5ed437810c353d83faddf7ff0fc2f4a106a9bd69d35b4d46e8b0ea870bbc6e7b0d68592a3b1feb3bc8870242859ba9176e3e1f6ea1f22ad4b3279eeb'},
 {'Name': 'New Mexico',
  'Vote': 'D',
  'Count': 5,
  'PK': 'ad6f4aebbb322725bef2e4db78c0831e0ec5796386baaeb06129f4709b5f904fefa062ddddbc2126a2cd523c41780f66',
  'Sign': 'b80a6d804b142872428870892581f5af9c87720d38dd840ea092a40e15203cbee8f7ecf6e0f7ebd7da80c26e3b3bbb84022f63ba5985d077197e0dc9ff8c66e5a205b5a637d3087f27862fedb01bbf8333eefab7e152846672a7c17ecc4bff31'},
 {'Name': 'South Dakota',
  'Vote': 'R',
  'Count': 3,
  'PK': '916b270e535a31873cc4b642108cdec32461b97cee0f03e43eef53dbf10a39404f24c13f0ee6de8754b4ca631d1fa9c3',
  'Sign': '9249fb12a9b52a78cabf04d96db288b8d6ef1755d7ee35595e8701123423894dff0a6caa67bb371eb3d9064fab3102fe069c0f0b6fc9acbb2913af170fdc607292be8ff0e4658bede42a6ae4d343ac44333b7949a6b142ab355e2df9ca923282'},
 {'Name': 'New York',
  'Vote': 'D',
  'Count': 29,
  'PK': '8351c394427c42dcfe4b4d3e8884ad133350e23aaad0adfa6631c7b7dafd17415a5f601a11235361759470a6e93f1485',
  'Sign': 'aa62da4b5b01e4b835dab43da0ddb03f940483237c30f2e65f56bc4c25e4484590a6dac4b01d620a3512115866dbd6b11107af46539c8b62de9e9de88c4a263b6d50537e6fdfa6e886840dc506692f816492ceac1f9db03beae7ee66163e14b2'},
 {'Name': 'Wyoming',
  'Vote': 'R',
  'Count': 3,
  'PK': 'b1eab9298bc7c086f7869f46814bdaf3bff8b198db60917874a70f0e97cfda9f322e0b4b6a9cbab6b4cbba3a84bdb006',
  'Sign': '8618363bbfd3c1080afa7fce8292bb02b066fa33e3cde1cfcd74a5421365754a168b8876657ab161eeb83d3ca85c8c3f17ac346d3c8760c5d1f18fdcbe4019c38487df09637a32ef5c21b6f6b0508fbd8a04a663fd1bacfab4d3ddd60d35abbc'},
 {'Name': 'Virginia',
  'Vote': 'D',
  'Count': 13,
  'PK': '89739e025b68fc193aa16b86423b3e55d298159cfa6fa390c5310f4b32a4ff351478cf2a21861edbe98e870fe7754add',
  'Sign': '8255be26785f68af40d7ac56068d8c07b2dea1095ae6039884d4e6b440f993ed5a81e1d4bb8458abd09afaa4fe3e1a5015caee0725bd42f0f77028c35433b54edcf6cc8164a9a6eef7724d989f9cc00cfc1a712a22f0b98954d5bf6ddeeb3c02'},
 {'Name': 'Indiana',
  'Vote': 'R',
  'Count': 11,
  'PK': '92e6af6715944e85882b4db5bd47e6a6ed2596788f150e31176ae1c7ae5ba88e9c246ddd5ce795199cca742306e493b9',
  'Sign': '87b79fc114854d672d5da0a048b5eb321b9b576f76a4de8d06303a5f873628e460eec897e18f84db6c11ea13723d8c93017b3c9fd3d3e48e9e9274dcfd5240f67f776288cf68c4c7735a69ff41e8c3acca769ee1fdb7a1679246e0721bd3e9c6'},
 {'Name': 'Illinois',
  'Vote': 'D',
  'Count': 20,
  'PK': '850c655b2811652f3fed0f43dd1c5edd978d8c67ee3a249f4cb66c5c80659f2095da30304f68a2b332296ab2b76b1012',
  'Sign': 'af91fd175dc3d17974c4ac84e39d9900634261e5a02c67172f90c839b4d425dc77bcda3bd36dd448eb37cb95fc866cda19cc8972135da073e567355e19537de7f35fed780d1937fc58e3e22cc713ac69d673b29422163b0612ca639114cdf9c9'},
 {'Name': 'Kansas',
  'Vote': 'R',
  'Count': 6,
  'PK': 'a508cc71d1c4111eb2433d1b7cb695f365430099d393eb3afabaaa8640dfe29fa9076f3e1c5d9227e2ea9094c9a97d0b',
  'Sign': '8521439bf44bc2b8518869f7e68ea5252d5dda2003f25fa2a9d2ed2578d48b961fbeb1e760de8f69a9623714f99e475109cf381096841c78073a785c8a946c60e7c8be98f1bbffb74c226c0d2f79849428eab1e7bcc6f600e6d62430a831773e'},
 {'Name': 'New Jersey',
  'Vote': 'D',
  'Count': 14,
  'PK': 'a3dd014aec4284ddc13df43e2bca07849978ab15663be2a7631dcb0dbbfc38afb10a60d94d719f8083b8026239f17a7f',
  'Sign': 'ab4c35e2cafcc4b696c22fade3160f900129cac158d3538f0c4cf71598931f88477bf22b3c452ecad395d72d1efcc5f301cfa582a906b84533bdec104615e80485ff29c205c05ef83e2a5bb8f7387d2d9542d8f99c8b00a005e7e4ad6594d707'},
 {'Name': 'South Carolina',
  'Vote': 'R',
  'Count': 9,
  'PK': '97a83b23da756c3144d24811b609f15dd5bc6543a9af8bd23135a3873739a07abffd2c33ac0f0a4b2e4e3c42f07fa9c1',
  'Sign': 'b00029b273dcfda804ce7c0f0e244b77bc4122a95ae3708c27dd4bb24d771131b9fbf07be0b8d04d805b99990e3bbb650816435455cc67d1bddd7a85d427a7596127751bf8e18531abcf0fe935b114db85f6351b4fd07a70d8aad9f7c3a08912'},
 {'Name': 'Vermont',
  'Vote': 'D',
  'Count': 3,
  'PK': 'a0bfdf6835adaddea3d260d4026ade2b7a7259bd2a1e3b49ead47ea5dd48874b0e1b7708ee9d46ef02564de11d2a2e4d',
  'Sign': 'ac4c796dfc3b9212682894630819547656aca202948189bc452962f7f6b9b32f799c9fa47bbb2a93049f08a6e377d2250c29adace592ea84ea8644e48ec90990e2cbe74346721b654635dd627bfb993555a873bf878e6cdf5401713e702a2567'},
 {'Name': 'Alabama',
  'Vote': 'R',
  'Count': 9,
  'PK': 'ab7b278025304171157383bf9cb15aac892233fa1a58c948e8595ee664e16c2c0c994e82e5a384355d09c88030905ec1',
  'Sign': 'a2fb74a45910a9db512c93a39069291d466d2f8e4c7955b79d548cad46296ec249ef0e324ee4939076bfc2375c83db4513d6ac3c1c3eb9563ff71eeda224f6d11d853fd5318fb913428c91485fda1e7c35315f42dc2a1eec334584f21b9e3e7f'},
 {'Name': 'Connecticut',
  'Vote': 'D',
  'Count': 7,
  'PK': '8105b28a7af2ccaa53a27b4f044c82c1d7a2dcf5aa18e6370976c4d3c77247a6b59701d5f724656e81331c3e687fe479',
  'Sign': '937e27aa654a81ae56c975b07695298927d757aef06044792178d316877e87c61d2373162a4ac455733561b9aaeaf70f1912af0d975bdeaa03795b376e5f7115bc627468f4e4b3b5819a1f9b321df145dcd2b1e9902a0ff3500438cebed5f475'},
 {'Name': 'Oklahoma',
  'Vote': 'R',
  'Count': 7,
  'PK': 'a23fa4df95ad8a0f0b4fa414ddca1e8465eefffdae05f487b45c2f589ae1ee22ac7c78e92b6a5a307356e7d36d38c87f',
  'Sign': 'a4b2b046c8712004e071986677c4ee55b68ae85b3753d5d58e3dde329eb44c5c56681fb3a773b8c3279f44451d8f28a400350ff1e63ab7a4794c558ffd643f4d3bbf52a42253e5f5278818579168261fa9be52f0f4e812e425867d4f5143e009'},
 {'Name': 'Massachusetts',
  'Vote': 'D',
  'Count': 11,
  'PK': '95ef2b7f8e12e901ff0afa0d4bfcc9727c96a19ceb0c6ae779d12e56b3c66489ec0a3eab8857501d39e7ec09febe57d4',
  'Sign': '956fc8d13cbf23ef8a3237dbd8edd1b470e65488693d0abd4bfcb087b195391dba2b2d56577a85abc20e277721baf0f90932444658351abf8f61d054a680404e390f619e73578fded73f85d87395a66f5d1133a4acf0134954ba576df8cdb0e1'},
 {'Name': 'Arkansas',
  'Vote': 'R',
  'Count': 6,
  'PK': 'b45956fa419edcabcde7e9675a73c98cd9e117f46cb77a425b55a0d487c72b98f93823cefe66faf5104e3a81994d488f',
  'Sign': 'acc9d03e1a39d6a07d934b39908e5dd8999dd297715d5c4088c2b16a08375fc503dc29dd7221c7c8bb350991ce7383d0195d253f61dc36b707e087e356da6426d8d91b2cdf5ee56707b6b0e515278bcb1ab53139793e7903a0ecddb3a4c5abef'},
 {'Name': 'Rhode Island',
  'Vote': 'D',
  'Count': 4,
  'PK': 'ac35fab31447122802a833c4df8fc5191f859dbe76c8a26a9eab200ce060b8881fb5480c30c2423be88a318838e16c56',
  'Sign': '957d48c920074effa93c0d2d8ca2eb6d1bb147174a78696fbb5fa5fb026df12e458f118c1caf12b7cf1a6af065ad14f517765af2757300046f295732d99ee0ffc15549bcffec0dd5db7312b63016f0c11a3cbd0d18ac2b1571f96074252144ea'},
 {'Name': 'Mississippi',
  'Vote': 'R',
  'Count': 6,
  'PK': 'a7579e1e868b3e858141f5239c919fb0858db25743f22d51966fa34527a91194d59c2ec5cbd9b028242fafbb9f9512c1',
  'Sign': 'b376aa915d818a4f7046a34af35124521a058fa4374d2db8f824d4a2a3f1b699100c2116966e0c6ec936a140ec27c83017748e238eaf2defd758eca15de4da5c9927f97c93e58685f2a42bf3658d5c797711fbd8e4ffd336de0caf1d754a8160'},
 {'Name': 'Delaware',
  'Vote': 'D',
  'Count': 3,
  'PK': 'ac18e29423d7d1074a0d73c6cad08462f69833ff267e436012a40d98d964620e50b32486e7878e417e573894475687ca',
  'Sign': 'a65d489f4dafcbb2f194934e3184ad818c3a16dba3731d7a523842e8a4cd575e5da143d7b89dad389f60f520b4b42fae0f63eaa5bd96fac8b3ee7d7645d99316d8ac881915df89a4a20280453104be4b0f196f32955df14bb51403b886678c0f'},
 {'Name': 'Tennessee',
  'Vote': 'R',
  'Count': 11,
  'PK': '85fdd4ade2caec720a9b208ba4d26e399690ee6c978d79cb2f7a0b0ab406af1547cfb01a68720f5a71c34f9282cb2387',
  'Sign': '8ddd99e5bf409744641f4d5548f86ec608a651938e29df86fe0f08bd5aa571f8bf46225ee9aadf66c1eb45e60d53bbc901a9ff84daa0d8675b387bf62f1266b65e6aa7f51a121f389957beb099286e01beac6e4e246126c378f8f815a7edaa4b'},
 {'Name': 'Maryland',
  'Vote': 'D',
  'Count': 10,
  'PK': '93e8209177cc332c57d0c92edbfc722236f4dc1a8de1b98c4bd5c8f9027a678e90474bab85b3923b8557628f48a816bc',
  'Sign': '8e4b17d8e9f980a0974c1dd667b75f2e3386b40055c35642405ddcad39edda682bcb4c6f311a39d5b82b64d8dbed3cb0138ebf6bf38f574b32fc6c0127e62ea69dcb0fd7c6379f5fc4ab10a170372ac05055f2f5f282ad91fd9d911c32729971'},
 {'Name': 'Kentucky',
  'Vote': 'R',
  'Count': 8,
  'PK': '8975552e7e2975843b0d72d5e39052e8a6d5a76f9d5781234b78f26af2faa5718c5b62ffeb0a297d9f1565353fbb5243',
  'Sign': '9025e5b452349ed95fd32ba5222da63e377d7ae2c6df40795eb6d2eb32be2e0f218618f2abfe40e3011d6d10172d07ca14f534972555e02363958ef4af2ef2a6242b1eca0d26d93dcd22084657967719035b86069ebd2b105207f5988b4040eb'},
 {'Name': 'New Hampshire',
  'Vote': 'D',
  'Count': 4,
  'PK': 'adbf0aa527947f9600223ccdeb3eca7849b59c687572f691c07db8d058c70cdfba80a19f76aeec9caefbb7dcd3fa160b',
  'Sign': '91a24c21f0f4dbc6c3d7fda605f838b10f62e9f3dfed2432f66ed8860af26b8a1bff820a2a2da0834a61806ea7bb1221047c34cb86f5666aed90dee1ebe6ef298669621ea257db9a5ac518b917cf787d344a654084287820088b430182540e36'},
 {'Name': 'West Virginia',
  'Vote': 'R',
  'Count': 5,
  'PK': 'a8c2e910c5c106f9b7c3e16eee8651c65d80837905d5f14e5f79d23b4641dadd9069bddb06645d96d46cf1117222188e',
  'Sign': 'a94b931fd5ceb214292c86d8f02fd28933efbcb6764c110ff0b34572c6a979e76b77be329540f6f83b9ce0fc9c4638f8164327b7ffc803c8409f2c6d37f10ae5ed4a7aff27d34284d89f91e3dd136258e9f306cf7489d78cf18d6ce6111f0d24'},
 {'Name': 'Washington',
  'Vote': 'D',
  'Count': 12,
  'PK': '963c36b641eb4b4b777e19bd29b733cbc3733d85ebaa86dffef2f7c57479b2e1d0f87355eabddb0fd2a7b60215797104',
  'Sign': '85d681cd33bd774a6565810644d71d1629b46e79192bc6d4fc348b6e9830593f67adb2748e1d329b9b1072e52734eca80b318941380bd8e53f6e9ea656eb5e7a7c1d5b2b073d15b0034f58b60d7ebfe930a9a802a50b99c881a495fb3ca3e167'},
 {'Name': 'Missouri',
  'Vote': 'R',
  'Count': 10,
  'PK': '919806eabb4584837a6de87b1d995929bf17bf53f3901f1c8c2eb90ecf12fe710f5332f6115ac1452c9e831c6ccc5348',
  'Sign': 'b3df95de68eeab2e5eb3964e94ecfe2eb6f1332a7388dc2634c906994a581f6ed492385bbb4f1367c7a208731de7204504c911bb4b0c47980d227f8a85c9ae4301de9789bf9196c250e2d939f0f028040933f505e5a4f7b2565b3875ff04542a'},
 {'Name': 'Oregon',
  'Vote': 'D',
  'Count': 7,
  'PK': '8b8b600c3cb810bd2b19d2ba49bfa990ed5365abd3e34ff3df44d08727a43660dfa606ac1e26097a5e3125152b20daa0',
  'Sign': '96fd00ba8cc756144738be41c7d37c8d90dbdef0b69e257f843838063cd01d2ae984aff03c621d242010595d4ab0c05c0ede61fd5998b29f4642cd7755c2fc12339f2b197e7b46dd0db2acfb50dbfe22a1c463fcb2fcde0e2bc5c74e3faa18a0'},
 {'Name': 'Idaho',
  'Vote': 'R',
  'Count': 4,
  'PK': 'b82766688c226b8e5141d5dbf13b10f2a3fa96e5c615bdebc629dabb0d52503f2e1ff0caedbe4f19c7f8ec7dde08bd1c',
  'Sign': 'a78e556915df6438533714393f1212f5f77898825ebe4c6e3d9dc3e8207fdb281685150a332b7c75830b5cdf5670658e177f7451eb22e4176aa683c7bdbc755eb400a361e1385b29dbdaa76b1513eaef1e53ca7c0e6b645c9dfae7c69a60907f'},
 {'Name': 'California',
  'Vote': 'D',
  'Count': 55,
  'PK': 'a2bd334fe36e60d61fffbc367c5d91e4fce2f76a5e88baaca1c3346bd99482316e1a820aba4fa0bd7d5cb21ba1fb5899',
  'Sign': '948fe219b22bd3d14a2f282e33656d4910f25f1ed06d2aecada9f9f1fffaa4ab8c23de34b2b42ec1d413a2cab4af0cd9025551ec31058bd00c1d14a3cf4aa33d2035123d4d9ff7ca58bfc3cd7ed09b44fb85d254be79648916908de06271f4a3'},
 {'Name': 'Utah',
  'Vote': 'R',
  'Count': 6,
  'PK': '90fddb05be44dfb3882b6b9464fc6a8148a771c30949b49e127b5004298d8a8055c6a74e28919d96be350f53f56ece0c',
  'Sign': '927d9abc04d407d8627d758ea7456723a80d7d8c666d023305a368f7af1388c6ca6ffb86352d787fd7f0e2177fc78b1e026e5d96920034c9d8504bdcfc4a7133c1e9bde5e40bbe256688d47e0a4bddcb9e8d5d9b25b9179b8af5d0b1907b545b'},
 {'Name': 'Hawaii',
  'Vote': 'D',
  'Count': 4,
  'PK': '94a74b01df673281ad0057ea631b758ad339225a4581694a7e2f9e513fae8c02cefeb3bbc6d20981286459f58583bf22',
  'Sign': '943e350685a5e8340d136b5bc5bf2c1ab670b47efec014ae028ec1a5d671069e4ba4a2da12713551b9de6183c140e83a099d664d50067dc479e138522efec660126a59f2cf177021c14f0c372ac9afa6cce03b57458bfb8309f082da73ae7415'},
 {'Name': 'Ohio',
  'Vote': 'R',
  'Count': 18,
  'PK': '8ea313cf075966d690978e67b73eef63451e3c9706ee25923b566623fc4a29ae9a2a1c7700d3f0dc9a6a9bdd7df720cc',
  'Sign': 'a87aaa00c957fcc0b600db3572999c9fb14ebf41492dc10d615b9ef3d94bf2fe09194d51e43f18d6ef3acfe0c5e35bda04aeef7c696a19a597645a12946387c113581c3939e5600a4d8f86d97d79d97fd221e73fbf836188432e86a153832949'},
 {'Name': 'Minnesota',
  'Vote': 'D',
  'Count': 10,
  'PK': 'b18c524740cef248dd4e9ff46bda3166a7629a330cee0e4785ad00315c5e192aa61a51e15a98eee39cd3691e39788ddd',
  'Sign': 'a9fe29b3373d13fd9ee6d9dc530d92f4200544e0261ebe4be7e6d0e7312d7fb1a6964eb36ffd6300f2586f74289599f0162086f380cdabab51c8d5e7b7682ec82027e532b2efbfa8a76d2b71f428a30d98bad14b9ce43497fad946ffd70e73a8'},
 {'Name': 'Montana',
  'Vote': 'R',
  'Count': 3,
  'PK': 'ace4a5f2b90cceb22c84351abbe27346dc526f31facf9c8aaac18450cdd029910f2d6d59412b6bf4bdc4e96daf4374e5',
  'Sign': 'ae45bd87845048c43b061c08884b44e6edac9037e1d3b9890ecceb550f19f743bb222e3b1ff988ffb274b0051a2ab0b508c31c72e770a772f22fa52db649f3a2dd77bb411836c36c5b0e19be499d17876f5ddef8fc16b38361695935ce11d6e2'},
 {'Name': 'Arizona',
  'Vote': 'D',
  'Count': 11,
  'PK': '86206344443f4b63773da9ef8b84c1b616841ddb10f69c3db28ecd99522f11538dc33fa6903515b9791e002671a0ed97',
  'Sign': '94131d658f78010e5bb029391c98115638908a9fd84ad04dbc1d1704355f768060126c32143b9b2823a6bc92bbb9d41a0ed1e0834eddaeb51915db1022a0bf846d3570e0998ebd52ef70fe29c40d27ac287809a11a34c1672668e183dab66f3a'},
 {'Name': 'Iowa',
  'Vote': 'R',
  'Count': 6,
  'PK': '902f248bcfeb0eba3793fb7e61209aecffd5c2f8404e61dab476793b41fca3e39d980c9273a06401d2de54416ac7de2c',
  'Sign': 'aa1f75e15eac39cb23a83f14e9d768ff9e48f3a5f3ddf299e087c0c4fd1c70e7db98d6bfc5e28878cb5e4720bde8bfe2001ab4e6597c7de0c25c28a6f645e286406448b69253407b3a20cc97087f06eb5b3faaa0ffc4cc89439b289cfd23f347'},
 {'Name': 'Maine',
  'Vote': 'D',
  'Count': 4,
  'PK': 'a00bc266cf9a90012003614ce43b5e449db94a8f31c66d8d2b16c83e511dbbaab2ccaa3ceff38435f76ad459a9fcdab3',
  'Sign': 'a51b4be1c429e3d9db36ef588f62d6f898c5db070e4fca93a1991a10bcad9da587589f9beb05fbb514e73aa59b1ab99908de19c7f48198e9c691f28015e5dab09665c9a3d445dc9d5824af41aec31f2cf105a9ba34fa7e7c8193dd2eba99f728'},
 {'Name': 'Florida',
  'Vote': 'R',
  'Count': 29,
  'PK': 'aa5399ac175380e2532f010bd5c7f8a3d228ef6ece0e0832777c9275ee2872f960ec3c32b82b9b3d75d987a7163edb51',
  'Sign': '8bdfbe3920a1f0b71dcc015295f5cc276a030f334320a9845107bb1499dfb5bc4122a7fd0aaa57301e40cb95f00209d9075f8b3c1e55ce89a013e7ab2a480b81b3bbde07c3c0615d68b6d423e4821dee3f022db8ea1e25c96b2ee5f564d9435c'},
 {'Name': 'Wisconsin',
  'Vote': 'D',
  'Count': 10,
  'PK': 'ab49bb4a03b4159dd32ae5306241fe703060afa79f07d5ff3cf4946c134fc848a8b67e53bebc040841e271063f4d2aba',
  'Sign': '917dc3d288374b715ab2e6bedf67da6ea012fe1a193864e103e93095ac748d2051101117db5efcd70e898f251d02edbd0aee149221cfa03aeeb033919de4a4c8dbfa761ca2494d9c7535c36ab44dea22d4c83045da8e4759e301d7c1826a3f29'},
 {'Name': 'Texas',
  'Vote': 'R',
  'Count': 38,
  'PK': 'b89b7cc1728cefada730481b9d6cb4708cd8150d8c3b4adea8d0a88c7c956e7ee244d78ccd94395b3bdb46887502e791',
  'Sign': '87e5ccc99586777873994e12fd65e44402e5205e77de898992a0afb3d80fdbaaa65234db0c00821eb03bd27b92bae21f027927409929e793096d93f1f607b9c67cbe79303bfd06ed0487d3c7d0f28aedfc3f19129b7901b32200044430107d98'},
 {'Name': 'Michigan',
  'Vote': 'D',
  'Count': 16,
  'PK': 'ae29e8f4d3c7b814042d04d12930bfc6f78eb12f3b9233a3338fedf42b784b6de6b5d575a0dee6d14de1a5ab9baaf5d9',
  'Sign': 'a977d66e4fabaaa4d79e4d32f6b0d4e2901278d4e0d31e662af8929ac7ca540c377907b7e315b908f5e643e49b4a4fd914d90bb60305595ab6160cfbe0bbabb5c8a98f8ae37fc6af64faf7dbc35a6b55d7e8c3946dda6135a9332f484b818312'}]

def singlechecker(agg_pk, agg_sig, msg):
    final_exp = final_exponentiate(
        pairing(
            agg_sig, 
            G1, 
            final_exponentiate=False
        ) * 
        pairing(
            multiply(G2, hasher(msg)), 
            neg(agg_pk), 
            final_exponentiate=False
        )
    )
    isok = (final_exp == FQ12.one())
    return isok

def checker(data, msg):
    agg_pk = Z1
    agg_sig = Z2
    for i in range(len(data)):
        if data[i]["Vote"].encode() == msg:
            agg_pk = add(agg_pk, pubkey_to_G1(bytes.fromhex(data[i]["PK"])))
            agg_sig = add(agg_sig, signature_to_G2(bytes.fromhex(data[i]["Sign"])))
    isok = singlechecker(agg_pk, agg_sig, msg)
    print(isok)
    
def creator(name, vote, sig):
    # sig must be hex

    res = {
        "Name" : name, 
        "Vote" : vote, 
        "Sign" : sig
    }

    fin = json.dumps(res)
    return fin

def bytexor(a, b):
	assert len(a) == len(b)
	return bytes(x ^ y for x, y in zip(a, b))

def readlines(num, pr=False):
    for _ in range(num):
        s = r.recvline()
        if pr:
            print(s)



res = bytes.fromhex("0b0753071d4c2a7d2000055907315546000800450075585d6c1a6e2b115931393f5c534d480e4400")

cc = b"bi0s{7h1s_0n3_1s_n07_7h3_r1gh7_fl4g. :)}"

print(bytexor(cc, res))

exit()

# e(pub, msg) = e(G, sig)

# e(pub1 + .. + pubk, msg) = e(G, sig1 + ... + sign)

readlines(4, True)

checker(wow, b"R")
checker(wow, b"D")
ex = True

q = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab

cv = ((q ** 12) - 1) // 115

ex = True
cnt = 0

for i in range(len(wow)):
    #  res = singlechecker(pubkey_to_G1(bytes.fromhex(wow[i]["PK"])), signature_to_G2(bytes.fromhex(wow[i]["Sign"])), wow[i]["Vote"].encode())
    # print(res)
    pub = pubkey_to_G1(bytes.fromhex(wow[i]["PK"]))
    sig = signature_to_G2(bytes.fromhex(wow[i]["Sign"]))
    print("pubkey check", i, subgroup_check(pub))
    print("sig check", i, subgroup_check(sig))
    if wow[i]["Vote"] == "D":
        if ex:
            ex = False 
            fin = creator(wow[i]["Name"], "D", wow[i]["Sign"])
            r.sendline(fin)
            continue
        res1 = hasher(b"D")
        res2 = hasher(b"R")
        
        tt = (res2 * inverse(res1, cv)) % cv
        sigs = signature_to_G2(bytes.fromhex(wow[i]["Sign"]))
        sigs = multiply(sigs, tt)
        # do this part only if you want fake flag
        if cnt == 0:
            sigs = add(sigs, G2) 
        if cnt == 1:
            sigs = add(sigs, neg(G2))
        # end
        cnt += 1
        sig = G2_to_signature(sigs).hex()
        wow[i]["Sign"] = sig
        wow[i]["Vote"] = "R"
       
    fin = creator(wow[i]["Name"], "R", wow[i]["Sign"])
    pub = pubkey_to_G1(bytes.fromhex(wow[i]["PK"]))
    sig = signature_to_G2(bytes.fromhex(wow[i]["Sign"]))
    print("sig check2", i, subgroup_check(sig))

    r.sendline(fin)

checker(wow, b"R")
checker(wow, b"D")

readlines(4, True)


