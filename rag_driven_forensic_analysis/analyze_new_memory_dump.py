#!/usr/bin/env python3
# Program is developed on Ubuntu 22.04.2 and Python 3.10.12
# Program to perform RAG-driven forensic analysis on new memory dumps using Azure OpenAI and Qdrant vector DB.
# Program extracts indicators of compromise (IoCs) from memory dumps, queries vector DB, and uses LLM for analysis.
# Version: 1.0

import json
from openai import AzureOpenAI
import os
from qdrant_client import QdrantClient, models as qmodels
import sys
import re


from memory_extraction_functions import (
    extract_network_information_from_dump,
    extract_process_information_from_dump,
    extract_memory_maps_from_dump,
    extract_string_match_from_dump,
    extract_network_addr_details_from_dump,
    execute_system_command
)

from rag_utils import (
    rerank_with_bm25_and_set_similarity,
    build_forensics_messages
)

from html_utils import generate_html_report_from_json

debug = False

class NormalizeAndExtractRagAndQueryLLM:
    def __init__(self, dump_file_path):
        self.config_path = 'processing_config.json'
        self.config = self.load_config()
        self.dump_file = dump_file_path
        self.analysis_ioc = dict()
        self.indicators = dict()

        endpoint = os.getenv("ENDPOINT_URL", self.config["endpoint_url"])
        self.embedding_deployment = os.getenv("DEPLOYMENT_NAME", self.config["embedding_model"])  # Embedding model deployment name
        subscription_key = os.getenv("AZURE_OPENAI_API_KEY", self.config["open_ai_api_key"])

        # Initialize Azure OpenAI client
        self.azure_client = AzureOpenAI(
            azure_endpoint=endpoint,
            api_key=subscription_key,
            api_version=self.config["api_version"],
        )

        # GPT-5 setup
        self.gpt_deployment = os.getenv("DEPLOYMENT_NAME", self.config["gpt_model"])  # GPT model deployment name

        # Connect to local Qdrant
        self.qdrant_client = QdrantClient(host=self.config["qdrant_host"], port=self.config["qdrant_port"])

        self.process_information = {}
    
    def load_config(self):
        with open(self.config_path, "r") as f:
            return json.load(f)


    def extract_information_from_dump(self):
        extract_network_information_from_dump(self.dump_file, self.analysis_ioc, self.indicators, debug, self.process_information, collect_process_info=True)
        extract_process_information_from_dump(self.dump_file, self.analysis_ioc, self.indicators, debug, self.process_information, collect_process_info=True)
        extract_memory_maps_from_dump(self.dump_file, self.analysis_ioc, self.indicators, debug, self.process_information, collect_process_info=True)
        extract_network_addr_details_from_dump(self.dump_file, self.analysis_ioc, self.indicators, debug, self.process_information, collect_process_info=True)

        if debug:
            print("Analysis IoC Extracted:")
            print(json.dumps(self.analysis_ioc, indent=4))
            print("Process Information Extracted:")
            print(json.dumps(self.process_information, indent=4))
            print("Indicators:")
            print(json.dumps(self.indicators, indent=4))

    def validate_and_process_data(self, base_dump_name):
        print("Validating and Processing Extracted Data...")
        if self.analysis_ioc:
            for pid in self.analysis_ioc.keys():
                return self.query_vector_db_and_request_llm(pid, base_dump_name)

        else:
            print("No Indicators of Compromise found in the memory dump analysis.")
            return False

    def extract_network_interface_details_from_dump(self):
        print("Extracting Network Interface Details from Dump...")
        interface_info = execute_system_command(f"vol -f {self.dump_file} linux.ip.Addr | grep -v -E 'lo[[:space:]]'")
        if debug:
            print(interface_info)

    def refine_rag_results_and_generate_llm_prompt(self, pid, vector_db_query, vector_db_search_results):

        # Re-rank:
        ranked = rerank_with_bm25_and_set_similarity(
            points=vector_db_search_results,
            query_text=vector_db_query,
            query_indicators=self.indicators,
            include_tags_in_bm25=True,  # helps BM25 pick up domain terms present in tags
            weights={"dense": 0.5, "bm25": 0.3, "jacc": 0.2}
        )

        if debug:
            for r in ranked:
                print(f"\nID: {r['id']}")
                print(f"final={r['final_score']:.3f} | dense_norm={r['dense_norm']:.3f} | bm25_norm={r['bm25_norm']:.3f} | jaccard={r['jaccard']:.2f}")
                print(f"class: {r['classification']}")
                print(f"dtoks: {r['dtoks']}")
                print(f"text: {r['text_snippet']}...")

        # Build LLM messages:
        messages = build_forensics_messages(
            process_tree_json=self.process_information[pid],
            ranked=ranked,                        # from your re-ranker (with dtoks, scores, etc.)
            query_text=vector_db_query,                     # your query description
            query_indicators=self.indicators,    # the structured indicators you derived
            similarity_metric="jaccard",          # or "precision"
            min_threshold=0.6,                   # tune 0.6–0.85; 1.0 for equality
            exact_match_mode="coverage",          # "equality" (strict) or "coverage" (query ⊆ candidate)
            top_k=2,
            allow_fallback=False                  # recommended; prevents ineligible candidates from driving classification
        )

        if debug:
            print("\n=== LLM Messages ===")
            for msg in messages:
                role = msg["role"]
                content = msg["content"]
                print(f"\n--- {role.upper()} ---\n{json.dumps(content, indent=2) if isinstance(content, dict) else content}")

        return messages

    def query_vector_db(self, vector_db_query):
        print("Querying Vector DB...")
        embedding_response = self.azure_client.embeddings.create(
            model=self.embedding_deployment,
            input=vector_db_query
        )

        query_vector = embedding_response.data[0].embedding

        # if debug:
        #     print("Query Vector Generated:", query_vector)

        # Query Qdrant for similar documents
        vector_db_search_results = self.qdrant_client.search(
            collection_name=self.config["qdrant_collection"],
            query_vector=query_vector,
            limit=5,
            with_payload=True
        )
        if debug:
            print("Vector DB Search Results:")
            for result in vector_db_search_results:
                print(json.dumps(result.payload, indent=4))


        return vector_db_search_results
    
    def query_LLM_with_rag(self, messages):
        print("Querying LLM with RAG...")

        # Generate the completion
        completion = self.azure_client.chat.completions.create(
            model=self.gpt_deployment,
            messages=messages,
            max_completion_tokens=16384,
            stop=None,
            stream=False
        )

        response_content = completion.choices[0].message.content

        cleaned_content = re.sub(r"^```json\n|```$", "", response_content.strip())

        try:
            parsed_json = json.loads(cleaned_content)
            print("\n\nFinal LLM Analysis Output:\n")
            print(json.dumps(parsed_json, indent=4))
        except json.JSONDecodeError as e:
            print("\n\nFailed to parse JSON:", e)
            print("\n\nRaw content was:\n", cleaned_content)
            
        return cleaned_content

    def perform_memory_scan_on_suspicious_processes(self, pid, vector_db_search_results):
        print("Performing Memory Scan on Suspicious Processes...")
        strings_of_interest = []

        for item in vector_db_search_results:
            payload = getattr(item, 'payload', {})  # Safely get payload
            if payload and 'strings_of_interest' in payload:
                strings_of_interest.extend(payload['strings_of_interest'])

        if strings_of_interest:
            extract_string_match_from_dump(self.dump_file, self.analysis_ioc, self.indicators, strings_of_interest, debug, self.process_information, collect_process_info=True)

        if debug and self.process_information[pid]["YARAStrings"]:
            print("Malicious Strings found in Memory for the pid: {0}".format(pid))
            print("Analysis IoC Extracted:")
            print(json.dumps(self.analysis_ioc, indent=4))
            print("Yara Strings found:")
            print(json.dumps(self.process_information[pid]["YARAStrings"], indent=4))
            print("Indicators:")
            print(json.dumps(self.indicators, indent=4))

    def query_vector_db_and_request_llm(self, pid, base_dump_name):
        query_text = self.analysis_ioc.get(pid, [])
        vector_db_query = ""

        for text in query_text:
            vector_db_query += f"{text},"

        vector_db_query = vector_db_query.rstrip(",")

        if debug:
            print(f"\nProcessing PID: {pid} with Indicators: {query_text}")
            print(f"Vector DB Query: {vector_db_query}")

        vector_db_search_results = self.query_vector_db(vector_db_query)

        self.perform_memory_scan_on_suspicious_processes(pid, vector_db_search_results)

        if len(query_text) == 1 and query_text[0].startswith("ESTABLISHED"):
            print(f"Skipping LLM query for PID {pid} due to only having ESTABLISHED network connection indicator.")
            return False
        else:     
            messages = self.refine_rag_results_and_generate_llm_prompt(pid, vector_db_query, vector_db_search_results)

            output_response = self.query_LLM_with_rag(messages)

            generate_html_report_from_json(json.loads(output_response), f"{base_dump_name}_pid_{pid}_report.html")


if __name__ == "__main__":
    # Receiving dump file as command line argument
    if len(sys.argv) != 2:
        print("Usage: python analyze_new_memory_dump.py <path_to_memory_dump>")
        sys.exit(1)
    dump_file_path = sys.argv[1]

    base_dump_name = os.path.splitext(os.path.basename(dump_file_path))[0]
    
    rag_processor = NormalizeAndExtractRagAndQueryLLM(dump_file_path)
    rag_processor.extract_information_from_dump()
    rag_processor.validate_and_process_data(base_dump_name)
