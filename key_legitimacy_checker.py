from input_parser import *
import time
import os
import sys

def verify_keys(circuit_name):
    oracle_bench_file = "./tmp/oracle_subcircuits/circuit_trace_extract_" + circuit_name
    obfuscated_bench_file = "./tmp/netlist_subcircuits/circuit_trace_extract_" + circuit_name
    key_file_name = "./key_files/temp_keys.txt"
    global_key_file_name = "./key_files/final_keys.txt"
    oracle_output = parse_outputs(oracle_bench_file)[0]
    oracle_inputs = parse_inputs(oracle_bench_file)
    key_inputs = parse_keys(obfuscated_bench_file)
    
    key_vector_map = {}
    list_possible_keys = []
    key_file = open(key_file_name, "r")
    for key in key_file:
        key_vector_map[key[0: key.find("=")].strip()] = key[key.find("=")+1: len(key)].strip()
    key_file.close() 
    legitimate_keys = []
    key_vector_value = []
    key_vector_value_cur = []
    for key in key_inputs:
        if key_vector_map.get(key) != None:
            if key_vector_map.get(key) == "True":
                key_vector_value.append(True)
            else:
                key_vector_value.append(False)
        else:
            print("key file reading failed!! - %s"%((key)))
            exit()
    
    for i in range(len(key_inputs)):
        key_vector_value_cur.extend(key_vector_value)
        key_vector_value_cur[i] = not key_vector_value_cur[i]
        key_string = ""
        for key in key_vector_value_cur:
            if key == True:
                key_string += "1"
            else:
                key_string += "0"       
        shell_code = "./attack_tool/bin/neos -q " + oracle_bench_file + " " + obfuscated_bench_file +  " key=" + key_string + " > ./intermediate_scripts/shell_out.txt"
        os.system(shell_code)
        shell_out = open("./intermediate_scripts/shell_out.txt", "r")
        legitimacy_flag = False
        for line in shell_out:
            if line.find("equivalent") == -1:
                legitimacy_flag = True
        if legitimacy_flag == True:
            legitimate_keys.append(key_inputs[i])
        key_vector_value_cur.clear()
    key_file = open(key_file_name, "w")    
    for key in legitimate_keys:
        key_file.write(key + "=" + key_vector_map[key] + "\n")
    key_file.close()    
    key_list = []    
    final_key_file_read = open(global_key_file_name, "r")
    temp_key_read = open(key_file_name, "r")
    for key in final_key_file_read:
        key_list.append(key)  
    for key in temp_key_read:
        key_list.append(key)
    temp_key_read.close()    
    final_key_file_write = open(global_key_file_name, "w")    
    for key in key_list:
        final_key_file_write.write(key)
    final_key_file_write.close()            
  





