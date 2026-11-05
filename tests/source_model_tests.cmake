# Primary-source alignment checks. The scripts live with the archived evidence named
# by IPP_EVIDENCE_DIR, and compare production decoding with independently compiled
# reference code. They run serially because they write to shared paths.

if(NOT Python3_Interpreter_FOUND)
    message(FATAL_ERROR "Source-model tests require Python")
endif()
if(NOT IS_DIRECTORY "${IPP_EVIDENCE_DIR}")
    message(FATAL_ERROR "IPP_SOURCE_MODEL_TESTS requires IPP_EVIDENCE_DIR")
endif()

# ipp_add_source_model(<test-name> <script> <timeout-seconds> [extra args...])
function(ipp_add_source_model test_name script timeout)
    set(script_path "${IPP_EVIDENCE_DIR}/${script}")
    if(NOT EXISTS "${script_path}")
        message(FATAL_ERROR
            "${test_name} requires ${script} in IPP_EVIDENCE_DIR")
    endif()
    add_test(NAME ${test_name}
        COMMAND ${Python3_EXECUTABLE} -I "${script_path}" --decoder $<TARGET_FILE:ipp-dec> ${ARGN})
    set_tests_properties(${test_name} PROPERTIES RUN_SERIAL TRUE TIMEOUT ${timeout})
endfunction()

ipp_add_cpp_test(ipp-register-views register_views.cpp)

ipp_add_source_model(madd-source-model fma_model.py 120)
ipp_add_source_model(pair-move-source-model pair_move_model.py 120)
ipp_add_source_model(system-state-corpus system_state_audit.py 120)
ipp_add_source_model(fp-alias-source-model fp_alias_model.py 300
    --views-provider $<TARGET_FILE:ipp-register-views>)
ipp_add_source_model(jpeg-scalar-source-model jpeg_scalar_model.py 120)
ipp_add_source_model(blend-source-model vector-pool-audit/blend.py 120)
ipp_add_source_model(fdct-source-model dct-pool-audit/fdct_model.py 180)
ipp_add_source_model(idct-dc-source-model dct-pool-audit/idct_dc_model.py 180)
ipp_add_source_model(outline-source-model dct-pool-audit/outline_model.py 180)
ipp_add_source_model(idct-full-source-model idct-full-audit/idct_model.py 180)
ipp_add_source_model(compact-shift-model shift-count-audit/shift_model.py 120)
ipp_add_source_model(dpp-product-constraints dpp_product_audit.py 120)
ipp_add_source_model(branch-encoder-model v8_branch_model.py 120
    --library $<TARGET_FILE:ippdec>)
ipp_add_source_model(quad-scratch-constraints quad_scratch_audit.py 180)
