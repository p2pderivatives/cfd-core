#include "gtest/gtest.h"
#include <map>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_hdwallet.h"

// The main function are using gtest's main().

using cfd::core::ByteData;
using cfd::core::CfdException;
using cfd::core::HardenedType;
using cfd::core::KeyData;
using cfd::core::ByteData256;
using cfd::core::ExtPubkey;
using cfd::core::ExtPrivkey;
using cfd::core::NetType;
using cfd::core::Pubkey;
using cfd::core::Privkey;

TEST(KeyData, Constructor) {
  KeyData empty_obj;
  EXPECT_FALSE(empty_obj.IsValid());
}

TEST(KeyData, Pubkey1) {
  Pubkey pubkey1("021362bdf255b304dcd29bfdb6b5c63c68ef7df60e2b1fc156716efe077b794647");
  ByteData fingerprint1("12345678");
  std::vector<uint32_t> array1{0, 1, 2};

  auto check_func = [](const KeyData& obj, const std::vector<uint32_t>& arr_obj) {
    auto obj_arr = obj.GetChildNumArray();
    EXPECT_TRUE(obj.IsValid());
    EXPECT_FALSE(obj.HasPrivkey());
    EXPECT_FALSE(obj.HasExtPubkey());
    EXPECT_FALSE(obj.HasExtPrivkey());
    EXPECT_EQ(arr_obj.size(), obj_arr.size());
    EXPECT_STREQ("0/1/2", obj.GetBip32Path().c_str());
    EXPECT_STREQ("12345678", obj.GetFingerprint().GetHex().c_str());
    EXPECT_STREQ(
        "021362bdf255b304dcd29bfdb6b5c63c68ef7df60e2b1fc156716efe077b794647",
        obj.GetPubkey().GetHex().c_str());
    for (size_t idx=0; idx<arr_obj.size(); ++idx) {
      EXPECT_EQ(arr_obj[idx], obj_arr[idx]);
    }
    EXPECT_STREQ(
        "[12345678/0/1/2]021362bdf255b304dcd29bfdb6b5c63c68ef7df60e2b1fc156716efe077b794647",
        obj.ToString().c_str());
    EXPECT_STREQ("0x0/0x1/0x2",
        obj.GetBip32Path(HardenedType::kApostrophe, true).c_str());
  };

  KeyData obj1(pubkey1, "0/1/2", fingerprint1);
  check_func(obj1, array1);
  KeyData obj2(pubkey1, array1, fingerprint1);
  check_func(obj2, array1);
}

TEST(KeyData, Privkey_mainnet) {
  Privkey privkey1 = Privkey::FromWif("KxqjPLtQqydD8d6eUrpJ7Q1266k8Mw8f5eoyEztY3Kc5z4f2RQTG");
  ByteData fingerprint1("3456789a");
  std::vector<uint32_t> array1{0x80000001, 2, 0x80000003};

  auto check_func = [](const KeyData& obj, const std::vector<uint32_t>& arr_obj) {
    auto obj_arr = obj.GetChildNumArray();
    EXPECT_TRUE(obj.IsValid());
    EXPECT_TRUE(obj.HasPrivkey());
    EXPECT_FALSE(obj.HasExtPubkey());
    EXPECT_FALSE(obj.HasExtPrivkey());
    EXPECT_EQ(arr_obj.size(), obj_arr.size());
    EXPECT_STREQ("1'/2/3'", obj.GetBip32Path().c_str());
    EXPECT_STREQ("3456789a", obj.GetFingerprint().GetHex().c_str());
    EXPECT_STREQ(
        "KxqjPLtQqydD8d6eUrpJ7Q1266k8Mw8f5eoyEztY3Kc5z4f2RQTG",
        obj.GetPrivkey().GetWif().c_str());
    EXPECT_STREQ(
        "031777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb",
        obj.GetPubkey().GetHex().c_str());
    for (size_t idx=0; idx<arr_obj.size(); ++idx) {
      EXPECT_EQ(arr_obj[idx], obj_arr[idx]);
    }
    EXPECT_STREQ(
        "[3456789a/1'/2/3']031777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb",
        obj.ToString().c_str());
    EXPECT_STREQ("0x80000001/0x2/0x80000003",
        obj.GetBip32Path(HardenedType::kNumber, true).c_str());

    EXPECT_STREQ(
        "[3456789a/1h/2/3h]KxqjPLtQqydD8d6eUrpJ7Q1266k8Mw8f5eoyEztY3Kc5z4f2RQTG",
        obj.ToString(false, HardenedType::kSmallH).c_str());
  };

  KeyData obj1(privkey1, "1'/2/0x80000003", fingerprint1);
  check_func(obj1, array1);
  KeyData obj2(privkey1, array1, fingerprint1);
  check_func(obj2, array1);
  KeyData obj3(privkey1, "1h/2/3H", fingerprint1);
  check_func(obj3, array1);
}

TEST(KeyData, Privkey_testnet) {
  Privkey privkey1 = Privkey::FromWif("cQNmd1D8MqzijUuXHb2yS5oRSm2F3TSTTMvcHC3V7CiKxArpg1bg");
  ByteData fingerprint1("3456789a");
  std::vector<uint32_t> array1{0x80000001, 2, 0x80000003};

  auto check_func = [](const KeyData& obj, const std::vector<uint32_t>& arr_obj) {
    auto obj_arr = obj.GetChildNumArray();
    EXPECT_TRUE(obj.IsValid());
    EXPECT_TRUE(obj.HasPrivkey());
    EXPECT_FALSE(obj.HasExtPubkey());
    EXPECT_FALSE(obj.HasExtPrivkey());
    EXPECT_EQ(arr_obj.size(), obj_arr.size());
    EXPECT_STREQ("1'/2/3'", obj.GetBip32Path().c_str());
    EXPECT_STREQ("3456789a", obj.GetFingerprint().GetHex().c_str());
    EXPECT_STREQ(
        "cQNmd1D8MqzijUuXHb2yS5oRSm2F3TSTTMvcHC3V7CiKxArpg1bg",
        obj.GetPrivkey().GetWif().c_str());
    EXPECT_STREQ(
        "02e3cf2c4dca39b502a6f8ba37e5d63a9757492c2155bf99418d9532728cd23d93",
        obj.GetPubkey().GetHex().c_str());
    for (size_t idx=0; idx<arr_obj.size(); ++idx) {
      EXPECT_EQ(arr_obj[idx], obj_arr[idx]);
    }
    EXPECT_STREQ(
        "[3456789a/1'/2/3']02e3cf2c4dca39b502a6f8ba37e5d63a9757492c2155bf99418d9532728cd23d93",
        obj.ToString().c_str());
    EXPECT_STREQ("0x80000001/0x2/0x80000003",
        obj.GetBip32Path(HardenedType::kNumber, true).c_str());

    EXPECT_STREQ(
        "[3456789a/1h/2/3h]cQNmd1D8MqzijUuXHb2yS5oRSm2F3TSTTMvcHC3V7CiKxArpg1bg",
        obj.ToString(false, HardenedType::kSmallH).c_str());
  };

  KeyData obj1(privkey1, "1'/2/0x80000003", fingerprint1);
  check_func(obj1, array1);
  KeyData obj2(privkey1, array1, fingerprint1);
  check_func(obj2, array1);
  KeyData obj3(privkey1, "1h/2/3H", fingerprint1);
  check_func(obj3, array1);
}

TEST(KeyData, Extpubkey1) {
  ExtPubkey key1 = ExtPubkey("tpubDF7yNiHQHdfns9Mc3XM7PYcS2dqrPqcit3FLkebvHxS4atZxifANou2KTvpQQQP82ANDCkPc5MPQZ28pjYGgmDXGy1iyzaiX6MTBv8i4cua");
  ByteData fingerprint1("3456789a");
  std::vector<uint32_t> array1{0x80000001, 2, 0x80000003};

  auto check_func = [](const KeyData& obj, const std::vector<uint32_t>& arr_obj) {
    auto obj_arr = obj.GetChildNumArray();
    EXPECT_TRUE(obj.IsValid());
    EXPECT_FALSE(obj.HasPrivkey());
    EXPECT_TRUE(obj.HasExtPubkey());
    EXPECT_FALSE(obj.HasExtPrivkey());
    EXPECT_EQ(arr_obj.size(), obj_arr.size());
    EXPECT_STREQ("1'/2/3'", obj.GetBip32Path().c_str());
    EXPECT_STREQ("3456789a", obj.GetFingerprint().GetHex().c_str());
    EXPECT_STREQ(
        "tpubDF7yNiHQHdfns9Mc3XM7PYcS2dqrPqcit3FLkebvHxS4atZxifANou2KTvpQQQP82ANDCkPc5MPQZ28pjYGgmDXGy1iyzaiX6MTBv8i4cua",
        obj.GetExtPubkey().ToString().c_str());
    EXPECT_STREQ(
        "03f1e767c0555ce0105b2a76d0f8b19b6d33a147f82f75a05c4c09580c39694fd3",
        obj.GetPubkey().GetHex().c_str());
    for (size_t idx=0; idx<arr_obj.size(); ++idx) {
      EXPECT_EQ(arr_obj[idx], obj_arr[idx]);
    }
    EXPECT_STREQ(
        "[3456789a/1'/2/3']03f1e767c0555ce0105b2a76d0f8b19b6d33a147f82f75a05c4c09580c39694fd3",
        obj.ToString().c_str());
    EXPECT_STREQ("0x80000001/0x2/0x80000003",
        obj.GetBip32Path(HardenedType::kNumber, true).c_str());

    EXPECT_STREQ(
        "[3456789a/1h/2/3h]tpubDF7yNiHQHdfns9Mc3XM7PYcS2dqrPqcit3FLkebvHxS4atZxifANou2KTvpQQQP82ANDCkPc5MPQZ28pjYGgmDXGy1iyzaiX6MTBv8i4cua",
        obj.ToString(false, HardenedType::kSmallH).c_str());
  };

  KeyData obj1(key1, "1'/2/0x80000003", fingerprint1);
  check_func(obj1, array1);
  KeyData obj2(key1, array1, fingerprint1);
  check_func(obj2, array1);
  KeyData obj3(key1, "1h/2/3H", fingerprint1);
  check_func(obj3, array1);
}

TEST(KeyData, Extprivkey1) {
  ExtPrivkey key1 = ExtPrivkey("xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV");
  ByteData fingerprint1("3456789a");
  std::vector<uint32_t> array1{0x80000001, 2, 0x80000003};

  auto check_func = [](const KeyData& obj, const std::vector<uint32_t>& arr_obj) {
    auto obj_arr = obj.GetChildNumArray();
    EXPECT_TRUE(obj.IsValid());
    EXPECT_TRUE(obj.HasPrivkey());
    EXPECT_TRUE(obj.HasExtPubkey());
    EXPECT_TRUE(obj.HasExtPrivkey());
    EXPECT_EQ(arr_obj.size(), obj_arr.size());
    EXPECT_STREQ("1'/2/3'", obj.GetBip32Path().c_str());
    EXPECT_STREQ("3456789a", obj.GetFingerprint().GetHex().c_str());
    EXPECT_STREQ(
        "xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV",
        obj.GetExtPrivkey().ToString().c_str());
    EXPECT_STREQ(
        "038746b92b722894e533dbbda3fb7fa673da00f4b309bf98a2cf586c27100004b0",
        obj.GetPubkey().GetHex().c_str());
    for (size_t idx=0; idx<arr_obj.size(); ++idx) {
      EXPECT_EQ(arr_obj[idx], obj_arr[idx]);
    }
    EXPECT_STREQ(
        "[3456789a/1'/2/3']038746b92b722894e533dbbda3fb7fa673da00f4b309bf98a2cf586c27100004b0",
        obj.ToString().c_str());
    EXPECT_STREQ("0x80000001/0x2/0x80000003",
        obj.GetBip32Path(HardenedType::kNumber, true).c_str());

    EXPECT_STREQ(
        "[3456789a/1h/2/3h]xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV",
        obj.ToString(false, HardenedType::kSmallH).c_str());
  };

  KeyData obj1(key1, "1'/2/0x80000003", fingerprint1);
  check_func(obj1, array1);
  KeyData obj2(key1, array1, fingerprint1);
  check_func(obj2, array1);
  KeyData obj3(key1, "1h/2/3H", fingerprint1);
  check_func(obj3, array1);
}

TEST(KeyData, FromStringExtPrivkey) {
  std::string key1 = "[3456789a/1h/2/3h]xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV";
  std::vector<uint32_t> array1{0x80000001, 2, 0x80000003};

  auto check_func = [](const KeyData& obj, const std::vector<uint32_t>& arr_obj) {
    auto obj_arr = obj.GetChildNumArray();
    EXPECT_TRUE(obj.IsValid());
    EXPECT_TRUE(obj.HasPrivkey());
    EXPECT_TRUE(obj.HasExtPubkey());
    EXPECT_TRUE(obj.HasExtPrivkey());
    EXPECT_EQ(arr_obj.size(), obj_arr.size());
    EXPECT_STREQ("1'/2/3'", obj.GetBip32Path().c_str());
    EXPECT_STREQ("3456789a", obj.GetFingerprint().GetHex().c_str());
    EXPECT_STREQ(
        "xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV",
        obj.GetExtPrivkey().ToString().c_str());
    EXPECT_STREQ(
        "038746b92b722894e533dbbda3fb7fa673da00f4b309bf98a2cf586c27100004b0",
        obj.GetPubkey().GetHex().c_str());
    for (size_t idx=0; idx<arr_obj.size(); ++idx) {
      EXPECT_EQ(arr_obj[idx], obj_arr[idx]);
    }
    EXPECT_STREQ(
        "[3456789a/1'/2/3']038746b92b722894e533dbbda3fb7fa673da00f4b309bf98a2cf586c27100004b0",
        obj.ToString().c_str());
    EXPECT_STREQ("0x80000001/0x2/0x80000003",
        obj.GetBip32Path(HardenedType::kNumber, true).c_str());

    EXPECT_STREQ(
        "[3456789a/1h/2/3h]xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV",
        obj.ToString(false, HardenedType::kSmallH).c_str());
  };

  KeyData obj1;
  try {
    obj1 = KeyData(key1);
    check_func(obj1, array1);
  } catch (const CfdException& e) {
    EXPECT_STREQ("", e.what());
  }
}

TEST(KeyData, FromStringExtPrivkeyDerive) {
  std::string key1 = "[3456789a/1h/2/3h]xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV/0h/1";
  std::vector<uint32_t> array1{0x80000001, 2, 0x80000003, 0x80000000, 1};

  auto check_func = [](const KeyData& obj, const std::vector<uint32_t>& arr_obj) {
    auto obj_arr = obj.GetChildNumArray();
    EXPECT_TRUE(obj.IsValid());
    EXPECT_TRUE(obj.HasPrivkey());
    EXPECT_TRUE(obj.HasExtPubkey());
    EXPECT_TRUE(obj.HasExtPrivkey());
    EXPECT_EQ(arr_obj.size(), obj_arr.size());
    EXPECT_STREQ("1'/2/3'/0'/1", obj.GetBip32Path().c_str());
    EXPECT_STREQ("3456789a", obj.GetFingerprint().GetHex().c_str());
    EXPECT_STREQ(
        "xprvA4VvhNxX2aGK493zrwSDXjMPmt3tSyU3V76RkSSkexsoshMJvD4FfYdZJLTRrYaK2rg16qPEmg4KcwDnJ6VNwynQArQorw9R9fe1XZqTgKf",
        obj.GetExtPrivkey().ToString().c_str());
    EXPECT_STREQ(
        "02a6f2b5dc540788a972bf7e2e5f6275e3b78375cc8739ebc0bc509f06bb0a38c4",
        obj.GetPubkey().GetHex().c_str());
    for (size_t idx=0; idx<arr_obj.size(); ++idx) {
      EXPECT_EQ(arr_obj[idx], obj_arr[idx]);
    }
    EXPECT_STREQ(
        "[3456789a/1'/2/3'/0'/1]02a6f2b5dc540788a972bf7e2e5f6275e3b78375cc8739ebc0bc509f06bb0a38c4",
        obj.ToString().c_str());
    EXPECT_STREQ("0x80000001/0x2/0x80000003/0x80000000/0x1",
        obj.GetBip32Path(HardenedType::kNumber, true).c_str());

    EXPECT_STREQ(
        "[3456789a/1h/2/3h/0h/1]xprvA4VvhNxX2aGK493zrwSDXjMPmt3tSyU3V76RkSSkexsoshMJvD4FfYdZJLTRrYaK2rg16qPEmg4KcwDnJ6VNwynQArQorw9R9fe1XZqTgKf",
        obj.ToString(false, HardenedType::kSmallH).c_str());
  };

  KeyData obj1;
  try {
    obj1 = KeyData(key1);
    check_func(obj1, array1);
  } catch (const CfdException& e) {
    EXPECT_STREQ("", e.what());
  }
}

TEST(KeyData, FromStringExtPubkey) {
  std::string key1 = "[3456789a/1h/2/3h]tpubDF7yNiHQHdfns9Mc3XM7PYcS2dqrPqcit3FLkebvHxS4atZxifANou2KTvpQQQP82ANDCkPc5MPQZ28pjYGgmDXGy1iyzaiX6MTBv8i4cua";
  std::vector<uint32_t> array1{0x80000001, 2, 0x80000003};

  auto check_func = [](const KeyData& obj, const std::vector<uint32_t>& arr_obj) {
    auto obj_arr = obj.GetChildNumArray();
    EXPECT_TRUE(obj.IsValid());
    EXPECT_FALSE(obj.HasPrivkey());
    EXPECT_TRUE(obj.HasExtPubkey());
    EXPECT_FALSE(obj.HasExtPrivkey());
    EXPECT_EQ(arr_obj.size(), obj_arr.size());
    EXPECT_STREQ("1'/2/3'", obj.GetBip32Path().c_str());
    EXPECT_STREQ("3456789a", obj.GetFingerprint().GetHex().c_str());
    EXPECT_STREQ(
        "tpubDF7yNiHQHdfns9Mc3XM7PYcS2dqrPqcit3FLkebvHxS4atZxifANou2KTvpQQQP82ANDCkPc5MPQZ28pjYGgmDXGy1iyzaiX6MTBv8i4cua",
        obj.GetExtPubkey().ToString().c_str());
    EXPECT_STREQ(
        "03f1e767c0555ce0105b2a76d0f8b19b6d33a147f82f75a05c4c09580c39694fd3",
        obj.GetPubkey().GetHex().c_str());
    for (size_t idx=0; idx<arr_obj.size(); ++idx) {
      EXPECT_EQ(arr_obj[idx], obj_arr[idx]);
    }
    EXPECT_STREQ(
        "[3456789a/1'/2/3']03f1e767c0555ce0105b2a76d0f8b19b6d33a147f82f75a05c4c09580c39694fd3",
        obj.ToString().c_str());
    EXPECT_STREQ("0x80000001/0x2/0x80000003",
        obj.GetBip32Path(HardenedType::kNumber, true).c_str());

    EXPECT_STREQ(
        "[3456789a/1h/2/3h]tpubDF7yNiHQHdfns9Mc3XM7PYcS2dqrPqcit3FLkebvHxS4atZxifANou2KTvpQQQP82ANDCkPc5MPQZ28pjYGgmDXGy1iyzaiX6MTBv8i4cua",
        obj.ToString(false, HardenedType::kSmallH).c_str());
  };

  KeyData obj1;
  try {
    obj1 = KeyData(key1);
    check_func(obj1, array1);
  } catch (const CfdException& e) {
    EXPECT_STREQ("", e.what());
  }
}

TEST(KeyData, FromStringExtPubkeyDerive) {
  std::string key1 = "[3456789a/1h/2/3h]tpubDF7yNiHQHdfns9Mc3XM7PYcS2dqrPqcit3FLkebvHxS4atZxifANou2KTvpQQQP82ANDCkPc5MPQZ28pjYGgmDXGy1iyzaiX6MTBv8i4cua/1/2";
  std::vector<uint32_t> array1{0x80000001, 2, 0x80000003, 1, 2};

  auto check_func = [](const KeyData& obj, const std::vector<uint32_t>& arr_obj) {
    auto obj_arr = obj.GetChildNumArray();
    EXPECT_TRUE(obj.IsValid());
    EXPECT_FALSE(obj.HasPrivkey());
    EXPECT_TRUE(obj.HasExtPubkey());
    EXPECT_FALSE(obj.HasExtPrivkey());
    EXPECT_EQ(arr_obj.size(), obj_arr.size());
    EXPECT_STREQ("1'/2/3'/1/2", obj.GetBip32Path().c_str());
    EXPECT_STREQ("3456789a", obj.GetFingerprint().GetHex().c_str());
    EXPECT_STREQ(
        "tpubDKETJ63aebYdrKgfJg1fAQXgiNX9WGC4YyAGU3o5F9xhqx3Q2Y2Qnn9d3LPG5wfajojW4PGmdcFJCGJaCL8mjcTAS2aD7uBS34zL5diACGD",
        obj.GetExtPubkey().ToString().c_str());
    EXPECT_STREQ(
        "038e04e1ba2657af7032efd287da4feaf47ac06bd18380595ae96bd626e8c2ad89",
        obj.GetPubkey().GetHex().c_str());
    for (size_t idx=0; idx<arr_obj.size(); ++idx) {
      EXPECT_EQ(arr_obj[idx], obj_arr[idx]);
    }
    EXPECT_STREQ(
        "[3456789a/1'/2/3'/1/2]038e04e1ba2657af7032efd287da4feaf47ac06bd18380595ae96bd626e8c2ad89",
        obj.ToString().c_str());
    EXPECT_STREQ("0x80000001/0x2/0x80000003/0x1/0x2",
        obj.GetBip32Path(HardenedType::kNumber, true).c_str());

    EXPECT_STREQ(
        "[3456789a/1h/2/3h/1/2]tpubDKETJ63aebYdrKgfJg1fAQXgiNX9WGC4YyAGU3o5F9xhqx3Q2Y2Qnn9d3LPG5wfajojW4PGmdcFJCGJaCL8mjcTAS2aD7uBS34zL5diACGD",
        obj.ToString(false, HardenedType::kSmallH).c_str());
  };

  KeyData obj1;
  try {
    obj1 = KeyData(key1);
    check_func(obj1, array1);
  } catch (const CfdException& e) {
    EXPECT_STREQ("", e.what());
  }

  // hardened error
  KeyData obj2;
  try {
    std::string key2 = "[3456789a/1h/2/3h]tpubDF7yNiHQHdfns9Mc3XM7PYcS2dqrPqcit3FLkebvHxS4atZxifANou2KTvpQQQP82ANDCkPc5MPQZ28pjYGgmDXGy1iyzaiX6MTBv8i4cua/1h/2";
    obj2 = KeyData(key2);
    EXPECT_FALSE(true);
  } catch (const CfdException& e) {
    EXPECT_STREQ("Failed to extPubkey. hardened is extPrivkey only.", e.what());
  }
  try {
    std::string key3 = "[3456789a/1h/2/3h]tpubDF7yNiHQHdfns9Mc3XM7PYcS2dqrPqcit3FLkebvHxS4atZxifANou2KTvpQQQP82ANDCkPc5MPQZ28pjYGgmDXGy1iyzaiX6MTBv8i4cua/0x80000001/2";
    obj2 = KeyData(key3);
    EXPECT_FALSE(true);
  } catch (const CfdException& e) {
    EXPECT_STREQ("Failed to extPubkey. hardened is extPrivkey only.", e.what());
  }
  try {
    std::string key4 = "[3456789a/1h/2/3h]tpubDF7yNiHQHdfns9Mc3XM7PYcS2dqrPqcit3FLkebvHxS4atZxifANou2KTvpQQQP82ANDCkPc5MPQZ28pjYGgmDXGy1iyzaiX6MTBv8i4cua/2147483648/2";
    obj2 = KeyData(key4);
    EXPECT_FALSE(true);
  } catch (const CfdException& e) {
    EXPECT_STREQ("Failed to extPubkey. hardened is extPrivkey only.", e.what());
  }
}

TEST(KeyData, FromStringPrivkeyWif) {
  std::string key1 = "[3456789a/1h/2/3h]KxqjPLtQqydD8d6eUrpJ7Q1266k8Mw8f5eoyEztY3Kc5z4f2RQTG";
  std::vector<uint32_t> array1{0x80000001, 2, 0x80000003};

  auto check_func = [](const KeyData& obj, const std::vector<uint32_t>& arr_obj) {
    auto obj_arr = obj.GetChildNumArray();
    EXPECT_TRUE(obj.IsValid());
    EXPECT_TRUE(obj.HasPrivkey());
    EXPECT_FALSE(obj.HasExtPubkey());
    EXPECT_FALSE(obj.HasExtPrivkey());
    EXPECT_EQ(arr_obj.size(), obj_arr.size());
    EXPECT_STREQ("1'/2/3'", obj.GetBip32Path().c_str());
    EXPECT_STREQ("3456789a", obj.GetFingerprint().GetHex().c_str());
    EXPECT_STREQ(
        "KxqjPLtQqydD8d6eUrpJ7Q1266k8Mw8f5eoyEztY3Kc5z4f2RQTG",
        obj.GetPrivkey().GetWif().c_str());
    EXPECT_STREQ(
        "031777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb",
        obj.GetPubkey().GetHex().c_str());
    for (size_t idx=0; idx<arr_obj.size(); ++idx) {
      EXPECT_EQ(arr_obj[idx], obj_arr[idx]);
    }
    EXPECT_STREQ(
        "[3456789a/1'/2/3']031777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb",
        obj.ToString().c_str());
    EXPECT_STREQ("0x80000001/0x2/0x80000003",
        obj.GetBip32Path(HardenedType::kNumber, true).c_str());

    EXPECT_STREQ(
        "[3456789a/1h/2/3h]KxqjPLtQqydD8d6eUrpJ7Q1266k8Mw8f5eoyEztY3Kc5z4f2RQTG",
        obj.ToString(false, HardenedType::kSmallH).c_str());
  };

  KeyData obj1;
  try {
    obj1 = KeyData(key1);
    check_func(obj1, array1);
  } catch (const CfdException& e) {
    EXPECT_STREQ("", e.what());
  }
}

TEST(KeyData, FromStringPrivkeyHex) {
  std::string key1 = "[3456789a/1h/2/3h]305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27";
  std::vector<uint32_t> array1{0x80000001, 2, 0x80000003};

  auto check_func = [](const KeyData& obj, const std::vector<uint32_t>& arr_obj) {
    auto obj_arr = obj.GetChildNumArray();
    EXPECT_TRUE(obj.IsValid());
    EXPECT_TRUE(obj.HasPrivkey());
    EXPECT_FALSE(obj.HasExtPubkey());
    EXPECT_FALSE(obj.HasExtPrivkey());
    EXPECT_EQ(arr_obj.size(), obj_arr.size());
    EXPECT_STREQ("1'/2/3'", obj.GetBip32Path().c_str());
    EXPECT_STREQ("3456789a", obj.GetFingerprint().GetHex().c_str());
    EXPECT_STREQ(
        "KxqjPLtQqydD8d6eUrpJ7Q1266k8Mw8f5eoyEztY3Kc5z4f2RQTG",
        obj.GetPrivkey().GetWif().c_str());
    EXPECT_STREQ(
        "305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27",
        obj.GetPrivkey().GetHex().c_str());
    EXPECT_STREQ(
        "031777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb",
        obj.GetPubkey().GetHex().c_str());
    for (size_t idx=0; idx<arr_obj.size(); ++idx) {
      EXPECT_EQ(arr_obj[idx], obj_arr[idx]);
    }
    EXPECT_STREQ(
        "[3456789a/1'/2/3']031777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb",
        obj.ToString().c_str());
    EXPECT_STREQ("0x80000001/0x2/0x80000003",
        obj.GetBip32Path(HardenedType::kNumber, true).c_str());

    EXPECT_STREQ(
        "[3456789a/1h/2/3h]KxqjPLtQqydD8d6eUrpJ7Q1266k8Mw8f5eoyEztY3Kc5z4f2RQTG",
        obj.ToString(false, HardenedType::kSmallH).c_str());
  };

  KeyData obj1;
  try {
    obj1 = KeyData(key1);
    check_func(obj1, array1);
  } catch (const CfdException& e) {
    EXPECT_STREQ("", e.what());
  }
}

TEST(KeyData, FromStringPubkey) {
  std::string key1 = "[12345678/0/1/2]021362bdf255b304dcd29bfdb6b5c63c68ef7df60e2b1fc156716efe077b794647";
  std::vector<uint32_t> array1{0, 1, 2};

  auto check_func = [](const KeyData& obj, const std::vector<uint32_t>& arr_obj) {
    auto obj_arr = obj.GetChildNumArray();
    EXPECT_TRUE(obj.IsValid());
    EXPECT_FALSE(obj.HasPrivkey());
    EXPECT_FALSE(obj.HasExtPubkey());
    EXPECT_FALSE(obj.HasExtPrivkey());
    EXPECT_EQ(arr_obj.size(), obj_arr.size());
    EXPECT_STREQ("0/1/2", obj.GetBip32Path().c_str());
    EXPECT_STREQ("12345678", obj.GetFingerprint().GetHex().c_str());
    EXPECT_STREQ(
        "021362bdf255b304dcd29bfdb6b5c63c68ef7df60e2b1fc156716efe077b794647",
        obj.GetPubkey().GetHex().c_str());
    for (size_t idx=0; idx<arr_obj.size(); ++idx) {
      EXPECT_EQ(arr_obj[idx], obj_arr[idx]);
    }
    EXPECT_STREQ(
        "[12345678/0/1/2]021362bdf255b304dcd29bfdb6b5c63c68ef7df60e2b1fc156716efe077b794647",
        obj.ToString().c_str());
    EXPECT_STREQ("0x0/0x1/0x2",
        obj.GetBip32Path(HardenedType::kApostrophe, true).c_str());
  };

  KeyData obj1;
  try {
    obj1 = KeyData(key1);
    check_func(obj1, array1);
  } catch (const CfdException& e) {
    EXPECT_STREQ("", e.what());
  }
}

TEST(KeyData, DerivePrivkey) {
  std::string key1 = "[3456789a/1h/2/3h]xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV";
  std::string path = "0h/1";
  std::vector<uint32_t> array1{0x80000001, 2, 0x80000003, 0x80000000, 1};
  std::vector<uint32_t> array2{0x80000000, 1};

  auto check_func = [](const KeyData& obj, const std::vector<uint32_t>& arr_obj) {
    auto obj_arr = obj.GetChildNumArray();
    EXPECT_TRUE(obj.IsValid());
    EXPECT_TRUE(obj.HasPrivkey());
    EXPECT_TRUE(obj.HasExtPubkey());
    EXPECT_TRUE(obj.HasExtPrivkey());
    EXPECT_EQ(arr_obj.size(), obj_arr.size());
    EXPECT_STREQ("1'/2/3'/0'/1", obj.GetBip32Path().c_str());
    EXPECT_STREQ("3456789a", obj.GetFingerprint().GetHex().c_str());
    EXPECT_STREQ(
        "xprvA4VvhNxX2aGK493zrwSDXjMPmt3tSyU3V76RkSSkexsoshMJvD4FfYdZJLTRrYaK2rg16qPEmg4KcwDnJ6VNwynQArQorw9R9fe1XZqTgKf",
        obj.GetExtPrivkey().ToString().c_str());
    EXPECT_STREQ(
        "02a6f2b5dc540788a972bf7e2e5f6275e3b78375cc8739ebc0bc509f06bb0a38c4",
        obj.GetPubkey().GetHex().c_str());
    for (size_t idx=0; idx<arr_obj.size(); ++idx) {
      EXPECT_EQ(arr_obj[idx], obj_arr[idx]);
    }
    EXPECT_STREQ(
        "[3456789a/1'/2/3'/0'/1]02a6f2b5dc540788a972bf7e2e5f6275e3b78375cc8739ebc0bc509f06bb0a38c4",
        obj.ToString().c_str());
    EXPECT_STREQ("0x80000001/0x2/0x80000003/0x80000000/0x1",
        obj.GetBip32Path(HardenedType::kNumber, true).c_str());

    EXPECT_STREQ(
        "[3456789a/1h/2/3h/0h/1]xprvA4VvhNxX2aGK493zrwSDXjMPmt3tSyU3V76RkSSkexsoshMJvD4FfYdZJLTRrYaK2rg16qPEmg4KcwDnJ6VNwynQArQorw9R9fe1XZqTgKf",
        obj.ToString(false, HardenedType::kSmallH).c_str());
  };

  KeyData obj1;
  try {
    obj1 = KeyData(key1);
    obj1 = obj1.DerivePrivkey(path, false);
    check_func(obj1, array1);
  } catch (const CfdException& e) {
    EXPECT_STREQ("", e.what());
  }

  auto check_func2 = [](const KeyData& obj, const std::vector<uint32_t>& arr_obj) {
    auto obj_arr = obj.GetChildNumArray();
    EXPECT_TRUE(obj.IsValid());
    EXPECT_TRUE(obj.HasPrivkey());
    EXPECT_TRUE(obj.HasExtPubkey());
    EXPECT_TRUE(obj.HasExtPrivkey());
    EXPECT_EQ(arr_obj.size(), obj_arr.size());
    EXPECT_STREQ("0'/1", obj.GetBip32Path().c_str());
    EXPECT_STREQ("ae05dbb7", obj.GetFingerprint().GetHex().c_str());
    EXPECT_STREQ(
        "xprvA4VvhNxX2aGK493zrwSDXjMPmt3tSyU3V76RkSSkexsoshMJvD4FfYdZJLTRrYaK2rg16qPEmg4KcwDnJ6VNwynQArQorw9R9fe1XZqTgKf",
        obj.GetExtPrivkey().ToString().c_str());
    EXPECT_STREQ(
        "02a6f2b5dc540788a972bf7e2e5f6275e3b78375cc8739ebc0bc509f06bb0a38c4",
        obj.GetPubkey().GetHex().c_str());
    for (size_t idx=0; idx<arr_obj.size(); ++idx) {
      EXPECT_EQ(arr_obj[idx], obj_arr[idx]);
    }
    EXPECT_STREQ(
        "[ae05dbb7/0'/1]02a6f2b5dc540788a972bf7e2e5f6275e3b78375cc8739ebc0bc509f06bb0a38c4",
        obj.ToString().c_str());
    EXPECT_STREQ("0x80000000/0x1",
        obj.GetBip32Path(HardenedType::kNumber, true).c_str());

    EXPECT_STREQ(
        "[ae05dbb7/0h/1]xprvA4VvhNxX2aGK493zrwSDXjMPmt3tSyU3V76RkSSkexsoshMJvD4FfYdZJLTRrYaK2rg16qPEmg4KcwDnJ6VNwynQArQorw9R9fe1XZqTgKf",
        obj.ToString(false, HardenedType::kSmallH).c_str());
  };

  KeyData obj2;
  try {
    obj2 = KeyData(key1);
    obj2 = obj2.DerivePrivkey(path, true);
    check_func2(obj2, array2);
  } catch (const CfdException& e) {
    EXPECT_STREQ("", e.what());
  }
}

TEST(KeyData, DerivePubkeyFromPrivkey) {
  std::string key1 = "[3456789a/1h/2/3h]xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV";
  std::string path = "0h/1";
  std::vector<uint32_t> array1{0x80000001, 2, 0x80000003, 0x80000000, 1};
  std::vector<uint32_t> array2{0x80000000, 1};

  auto check_func = [](const KeyData& obj, const std::vector<uint32_t>& arr_obj) {
    auto obj_arr = obj.GetChildNumArray();
    EXPECT_TRUE(obj.IsValid());
    EXPECT_FALSE(obj.HasPrivkey());
    EXPECT_TRUE(obj.HasExtPubkey());
    EXPECT_FALSE(obj.HasExtPrivkey());
    EXPECT_EQ(arr_obj.size(), obj_arr.size());
    EXPECT_STREQ("1'/2/3'/0'/1", obj.GetBip32Path().c_str());
    EXPECT_STREQ("3456789a", obj.GetFingerprint().GetHex().c_str());
    EXPECT_STREQ(
        "xpub6HVH6tVQrwpcGd8TxxyDtsJ8KutNrSBtrL22YprNDJQnkVgTTkNWDLx39bC6VALjHR73fZR8tuETUUNJqW9gbAoDjDoSTdVZp5kVKjG2pmx",
        obj.GetExtPubkey().ToString().c_str());
    EXPECT_STREQ(
        "02a6f2b5dc540788a972bf7e2e5f6275e3b78375cc8739ebc0bc509f06bb0a38c4",
        obj.GetPubkey().GetHex().c_str());
    for (size_t idx=0; idx<arr_obj.size(); ++idx) {
      EXPECT_EQ(arr_obj[idx], obj_arr[idx]);
    }
    EXPECT_STREQ(
        "[3456789a/1'/2/3'/0'/1]02a6f2b5dc540788a972bf7e2e5f6275e3b78375cc8739ebc0bc509f06bb0a38c4",
        obj.ToString().c_str());
    EXPECT_STREQ("0x80000001/0x2/0x80000003/0x80000000/0x1",
        obj.GetBip32Path(HardenedType::kNumber, true).c_str());

    EXPECT_STREQ(
        "[3456789a/1h/2/3h/0h/1]xpub6HVH6tVQrwpcGd8TxxyDtsJ8KutNrSBtrL22YprNDJQnkVgTTkNWDLx39bC6VALjHR73fZR8tuETUUNJqW9gbAoDjDoSTdVZp5kVKjG2pmx",
        obj.ToString(false, HardenedType::kSmallH).c_str());
  };

  KeyData obj1;
  try {
    obj1 = KeyData(key1);
    obj1 = obj1.DerivePubkey(path, false);
    check_func(obj1, array1);
  } catch (const CfdException& e) {
    EXPECT_STREQ("", e.what());
  }

  auto check_func2 = [](const KeyData& obj, const std::vector<uint32_t>& arr_obj) {
    auto obj_arr = obj.GetChildNumArray();
    EXPECT_TRUE(obj.IsValid());
    EXPECT_FALSE(obj.HasPrivkey());
    EXPECT_TRUE(obj.HasExtPubkey());
    EXPECT_FALSE(obj.HasExtPrivkey());
    EXPECT_EQ(arr_obj.size(), obj_arr.size());
    EXPECT_STREQ("0'/1", obj.GetBip32Path().c_str());
    EXPECT_STREQ("ae05dbb7", obj.GetFingerprint().GetHex().c_str());
    EXPECT_STREQ(
        "xpub6HVH6tVQrwpcGd8TxxyDtsJ8KutNrSBtrL22YprNDJQnkVgTTkNWDLx39bC6VALjHR73fZR8tuETUUNJqW9gbAoDjDoSTdVZp5kVKjG2pmx",
        obj.GetExtPubkey().ToString().c_str());
    EXPECT_STREQ(
        "02a6f2b5dc540788a972bf7e2e5f6275e3b78375cc8739ebc0bc509f06bb0a38c4",
        obj.GetPubkey().GetHex().c_str());
    for (size_t idx=0; idx<arr_obj.size(); ++idx) {
      EXPECT_EQ(arr_obj[idx], obj_arr[idx]);
    }
    EXPECT_STREQ(
        "[ae05dbb7/0'/1]02a6f2b5dc540788a972bf7e2e5f6275e3b78375cc8739ebc0bc509f06bb0a38c4",
        obj.ToString().c_str());
    EXPECT_STREQ("0x80000000/0x1",
        obj.GetBip32Path(HardenedType::kNumber, true).c_str());

    EXPECT_STREQ(
        "[ae05dbb7/0h/1]xpub6HVH6tVQrwpcGd8TxxyDtsJ8KutNrSBtrL22YprNDJQnkVgTTkNWDLx39bC6VALjHR73fZR8tuETUUNJqW9gbAoDjDoSTdVZp5kVKjG2pmx",
        obj.ToString(false, HardenedType::kSmallH).c_str());
  };

  KeyData obj2;
  try {
    obj2 = KeyData(key1);
    obj2 = obj2.DerivePubkey(path, true);
    check_func2(obj2, array2);
  } catch (const CfdException& e) {
    EXPECT_STREQ("", e.what());
  }
}

TEST(KeyData, DerivePubkey) {
  std::string key1 = "[3456789a/1h/2/3h]tpubDF7yNiHQHdfns9Mc3XM7PYcS2dqrPqcit3FLkebvHxS4atZxifANou2KTvpQQQP82ANDCkPc5MPQZ28pjYGgmDXGy1iyzaiX6MTBv8i4cua";
  std::string path = "1/2";
  std::vector<uint32_t> array1{0x80000001, 2, 0x80000003, 1, 2};
  std::vector<uint32_t> array2{1, 2};

  auto check_func = [](const KeyData& obj, const std::vector<uint32_t>& arr_obj) {
    auto obj_arr = obj.GetChildNumArray();
    EXPECT_TRUE(obj.IsValid());
    EXPECT_FALSE(obj.HasPrivkey());
    EXPECT_TRUE(obj.HasExtPubkey());
    EXPECT_FALSE(obj.HasExtPrivkey());
    EXPECT_EQ(arr_obj.size(), obj_arr.size());
    EXPECT_STREQ("1'/2/3'/1/2", obj.GetBip32Path().c_str());
    EXPECT_STREQ("3456789a", obj.GetFingerprint().GetHex().c_str());
    EXPECT_STREQ(
        "tpubDKETJ63aebYdrKgfJg1fAQXgiNX9WGC4YyAGU3o5F9xhqx3Q2Y2Qnn9d3LPG5wfajojW4PGmdcFJCGJaCL8mjcTAS2aD7uBS34zL5diACGD",
        obj.GetExtPubkey().ToString().c_str());
    EXPECT_STREQ(
        "038e04e1ba2657af7032efd287da4feaf47ac06bd18380595ae96bd626e8c2ad89",
        obj.GetPubkey().GetHex().c_str());
    for (size_t idx=0; idx<arr_obj.size(); ++idx) {
      EXPECT_EQ(arr_obj[idx], obj_arr[idx]);
    }
    EXPECT_STREQ(
        "[3456789a/1'/2/3'/1/2]038e04e1ba2657af7032efd287da4feaf47ac06bd18380595ae96bd626e8c2ad89",
        obj.ToString().c_str());
    EXPECT_STREQ("0x80000001/0x2/0x80000003/0x1/0x2",
        obj.GetBip32Path(HardenedType::kNumber, true).c_str());

    EXPECT_STREQ(
        "[3456789a/1h/2/3h/1/2]tpubDKETJ63aebYdrKgfJg1fAQXgiNX9WGC4YyAGU3o5F9xhqx3Q2Y2Qnn9d3LPG5wfajojW4PGmdcFJCGJaCL8mjcTAS2aD7uBS34zL5diACGD",
        obj.ToString(false, HardenedType::kSmallH).c_str());
  };

  KeyData obj1;
  try {
    obj1 = KeyData(key1);
    obj1 = obj1.DerivePubkey(path, false);
    check_func(obj1, array1);
  } catch (const CfdException& e) {
    EXPECT_STREQ("", e.what());
  }

  auto check_func2 = [](const KeyData& obj, const std::vector<uint32_t>& arr_obj) {
    auto obj_arr = obj.GetChildNumArray();
    EXPECT_TRUE(obj.IsValid());
    EXPECT_FALSE(obj.HasPrivkey());
    EXPECT_TRUE(obj.HasExtPubkey());
    EXPECT_FALSE(obj.HasExtPrivkey());
    EXPECT_EQ(arr_obj.size(), obj_arr.size());
    EXPECT_STREQ("1/2", obj.GetBip32Path().c_str());
    EXPECT_STREQ("40c902dd", obj.GetFingerprint().GetHex().c_str());
    EXPECT_STREQ(
        "tpubDKETJ63aebYdrKgfJg1fAQXgiNX9WGC4YyAGU3o5F9xhqx3Q2Y2Qnn9d3LPG5wfajojW4PGmdcFJCGJaCL8mjcTAS2aD7uBS34zL5diACGD",
        obj.GetExtPubkey().ToString().c_str());
    EXPECT_STREQ(
        "038e04e1ba2657af7032efd287da4feaf47ac06bd18380595ae96bd626e8c2ad89",
        obj.GetPubkey().GetHex().c_str());
    for (size_t idx=0; idx<arr_obj.size(); ++idx) {
      EXPECT_EQ(arr_obj[idx], obj_arr[idx]);
    }
    EXPECT_STREQ(
        "[40c902dd/1/2]038e04e1ba2657af7032efd287da4feaf47ac06bd18380595ae96bd626e8c2ad89",
        obj.ToString().c_str());
    EXPECT_STREQ("0x1/0x2",
        obj.GetBip32Path(HardenedType::kNumber, true).c_str());

    EXPECT_STREQ(
        "[40c902dd/1/2]tpubDKETJ63aebYdrKgfJg1fAQXgiNX9WGC4YyAGU3o5F9xhqx3Q2Y2Qnn9d3LPG5wfajojW4PGmdcFJCGJaCL8mjcTAS2aD7uBS34zL5diACGD",
        obj.ToString(false, HardenedType::kSmallH).c_str());
  };

  KeyData obj2;
  try {
    obj2 = KeyData(key1);
    obj2 = obj2.DerivePubkey(path, true);
    check_func2(obj2, array2);
  } catch (const CfdException& e) {
    EXPECT_STREQ("", e.what());
  }
}
