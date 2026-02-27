#!/usr/bin/env python3
import json
import nltk
from openai import AzureOpenAI
from openai import NotFoundError
import os
from qdrant_client import QdrantClient
from qdrant_client.models import PointStruct, VectorParams, Distance, CollectionStatus, PayloadSchemaType
import uuid

from memory_extraction_functions import (
    obtain_os_info_from_dump,
    extract_network_information_from_dump,
    extract_process_information_from_dump,
    extract_memory_maps_from_dump,
    extract_socket_redirections_from_lsof_output,
    extract_string_match_from_dump,
    process_windows_network_info_from_dump,
    obtain_process_with_suspicious_threads_from_dump,
    validate_sockets_for_suspicious_process,
    dump_suspicious_processes_with_sockets,
    delete_all_files_in_dumps_directory,
    check_suspicious_network_bytes_in_dump,
    extract_windows_yara_match_from_process_dumps
)


debug = True


class NormalizeAndIngestIntoVectorDB:

    def __init__(self):
        self.config_path = 'processing_config.json'
        self.config = self.load_config()

        endpoint = os.getenv("ENDPOINT_URL", self.config["endpoint_url"])
        self.embedding_deployment = os.getenv("DEPLOYMENT_NAME", self.config["embedding_model"])  # Embedding model deployment name
        subscription_key = os.getenv("AZURE_OPENAI_API_KEY", self.config["open_ai_api_key"])

        # Initialize Azure OpenAI client
        self.azure_client = AzureOpenAI(
            azure_endpoint=endpoint,
            api_key=subscription_key,
            api_version=self.config["api_version"],
        )

        # Connect to local Qdrant
        self.qdrant_client = QdrantClient(host=self.config["qdrant_host"], port=self.config["qdrant_port"])
        self.process_information = dict()


    def load_config(self):
        with open(self.config_path, "r") as f:
            return json.load(f)
        
    def process_memory_dumps(self):
        for dump_file, classification in self.config["memory_dumps_classification"].items():
            if debug:
                print(f"Processing dump file: {dump_file} with classification: {classification}")
            self.dump_file = os.path.join(self.config["memory_dumps_dir"], dump_file)
            self.classification = classification
            self.analysis_ioc = dict()
            self.structured_data = None
            self.indicators = dict()

            if "Reverse Shell" in self.classification or "Bind Shell" in self.classification:
                self.security_recommendations = self.config["RemoteShellRecommendations"]
            
            os_info = obtain_os_info_from_dump(self.dump_file)
            # print(f"Obtained OS Information: {os_info}")

            if os_info == "linux":
                extract_network_information_from_dump(self.dump_file, self.analysis_ioc, self.indicators, debug)
                extract_process_information_from_dump(self.dump_file, self.analysis_ioc, self.indicators, debug)
                extract_memory_maps_from_dump(self.dump_file, self.analysis_ioc, self.indicators, debug)
                extract_string_match_from_dump(self.dump_file, self.analysis_ioc, self.indicators, self.config["suspicious_strings"], debug, self.process_information, collect_process_info=True)
                extract_socket_redirections_from_lsof_output(self.dump_file, self.analysis_ioc, self.indicators, debug)
            elif os_info == "windows":
                suspicious_network_info = []

                susp_process = obtain_process_with_suspicious_threads_from_dump(self.dump_file, debug=False, top_n=5)
                # susp_pid_list = [item["pid"] for item in susp_threads]
                # print(susp_pid_list)
                susp_process_with_sockets = validate_sockets_for_suspicious_process(
                    self.dump_file,
                    susp_process,
                    self.analysis_ioc,
                    self.indicators,
                    debug
                )

                if debug:
                    print("Suspicious processes with socket handles:")
                    print(json.dumps(susp_process_with_sockets, indent=4))

                dump_results = dump_suspicious_processes_with_sockets(
                    self.dump_file,
                    susp_process_with_sockets,
                    dumps_dir="dumps",
                    debug=debug,
                )
                if debug:
                    print("Dump results for suspicious processes with sockets:")
                    print(json.dumps(dump_results, indent=4))

                process_windows_network_info_from_dump(self.dump_file, suspicious_network_info, debug)
                network_byte_matches = check_suspicious_network_bytes_in_dump(
                    suspicious_network_info,
                    susp_process=susp_process_with_sockets,
                    dumps_dir="dumps",
                    analysis_ioc=self.analysis_ioc,
                    indicators=self.indicators,
                    debug=debug,
                )
                if debug:
                    print("Suspicious network byte matches in dump:")
                    print(json.dumps(network_byte_matches, indent=4))

                extract_windows_yara_match_from_process_dumps(
                    analysis_ioc=self.analysis_ioc,
                    indicators=self.indicators,
                    strings_of_interest=self.config["suspicious_strings"],
                    dumps_dir="dumps",
                    debug=debug,
                    process_information=self.process_information,
                    collect_process_info=True,
                )

            
            if debug:
                print("Analysis IoC Extracted:")
                print(json.dumps(self.analysis_ioc, indent=4))
                print("Indicators:")
                print(json.dumps(self.indicators, indent=4))
                print(self.process_information)

            delete_all_files_in_dumps_directory(dumps_dir="dumps", debug=debug)
            self.generate_document_structure()
            self.generate_embedding_vector()

            if debug:
                print("Structured Data to be Ingested:")
                structured_data_copy = self.structured_data.copy()
                structured_data_copy.pop("vector", None)
                print(json.dumps(structured_data_copy, indent=4))

            self.upload_point_to_qdrant()


    def generate_document_structure(self):
        print("Generating Document Structure...")

        for pid, indicators in self.analysis_ioc.items():
            text = ", ".join(indicators) + "."
            # tags = list({tag for indicator in indicators for tag in indicator.split()})

            try:
                stop_words = set(nltk.corpus.stopwords.words('english'))
            except LookupError:
                nltk.download('stopwords')
                stop_words = set(nltk.corpus.stopwords.words('english'))

            tags = list({tag for indicator in indicators for tag in indicator.split() if tag.lower() not in stop_words})

            soi = []
            if "suspicious string match in memory" in indicators:
                process_yara = self.process_information.get(pid, {}).get("YARAStrings", [])
                for item in process_yara:
                    if isinstance(item, (list, tuple)) and len(item) >= 3:
                        soi.append(str(item[2]))
                    elif isinstance(item, str):
                        soi.append(item)

                    elif isinstance(item, dict):
                        for value in (item.get("YARAStrings") or item.get("matched_strings") or []):
                            if isinstance(value, str):
                                soi.append(value)

                # Deduplicate while preserving order
                soi = list(dict.fromkeys(soi))
                
            self.structured_data = {
                "id": str(uuid.uuid4()),
                "payload": {
                    "text": text,
                    "classification": self.classification,
                    "strings_of_interest": soi,
                    "source": self.config["classification_source"],
                    "indicators": self.indicators,
                    "security_recommendations": self.security_recommendations,
                    "tags": tags
                }
            }


    def generate_embedding_vector(self):
        print("Generating Embedding Vector...")

        response = self.azure_client.embeddings.create(
            model=self.embedding_deployment,
            input=self.structured_data["payload"]["text"]
        )

        # Extract the embedding vector
        embedding_vector = response.data[0].embedding

        self.structured_data["vector"] = embedding_vector

    def create_payload_index_for_collection(self):
        print("Creating Payload Index for Collection...")
        
        self.qdrant_client.create_payload_index(
            collection_name=self.config["qdrant_collection"],
            field_name="indicators.connection_facets",
            field_schema=PayloadSchemaType.KEYWORD,
        )
        self.qdrant_client.create_payload_index(
            collection_name=self.config["qdrant_collection"],
            field_name="indicators.rwx_to_main_binary",
            field_schema=PayloadSchemaType.BOOL,
        )
        self.qdrant_client.create_payload_index(
            collection_name=self.config["qdrant_collection"],
            field_name="indicators.rwx_to_anon_mapping",
            field_schema=PayloadSchemaType.BOOL,
        )
        
    def upload_point_to_qdrant(self):
        print("Uploading Point to Qdrant...")

        # Check if collection exists
        if not self.qdrant_client.collection_exists(self.config["qdrant_collection"]):
            self.qdrant_client.create_collection(
                collection_name=self.config["qdrant_collection"],
                vectors_config=VectorParams(size=len(self.structured_data["vector"]), distance=Distance.COSINE)
            )
            self.create_payload_index_for_collection()

        # Upload the point to Qdrant
        self.qdrant_client.upsert(
            collection_name=self.config["qdrant_collection"],
            points=[
                PointStruct(
                    id=self.structured_data["id"],
                    vector=self.structured_data["vector"],
                    payload=self.structured_data["payload"]
                )
            ]
        )

        print("Point ingested successfully!")


if __name__ == "__main__":
    extractor = NormalizeAndIngestIntoVectorDB()
    extractor.process_memory_dumps()
  