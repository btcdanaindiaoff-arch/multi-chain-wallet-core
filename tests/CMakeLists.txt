# =============================================================================
# wallet_core tests
# =============================================================================
find_package(GTest REQUIRED)

include(GoogleTest)

# Helper to add a test executable linked against wallet_core and GTest.
function(wallet_add_test TEST_NAME TEST_SOURCE)
    add_executable(${TEST_NAME} ${TEST_SOURCE})
    target_link_libraries(${TEST_NAME}
        PRIVATE
            wallet_core
            GTest::gtest
            GTest::gtest_main
    )
    gtest_discover_tests(${TEST_NAME})
endfunction()

wallet_add_test(test_crypto          test_crypto.cpp)
wallet_add_test(test_mnemonic        test_mnemonic.cpp)
wallet_add_test(test_key_derivation  test_key_derivation.cpp)
wallet_add_test(test_ethereum        test_ethereum.cpp)
wallet_add_test(test_bitcoin         test_bitcoin.cpp)
wallet_add_test(test_solana          test_solana.cpp)
