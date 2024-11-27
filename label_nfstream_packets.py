import warnings
warnings.filterwarnings("ignore")  # ignore UserWarnings

import click
from dpkt.pcap import UniversalReader
from dpkt.ethernet import Ethernet
from dpkt.ip import IP
from dpkt.tcp import TCP
from dpkt.udp import UDP
import multiprocessing as mp
import numpy as np
import os
import pandas as pd
import time
from tqdm import tqdm

from utils import gather_files, ip_to_str


@click.command()
@click.option(
    "-i",
    "--input-path",
    help="Path to input file or directory of PCAP/PCAPNG files to map",
    default="deduped",
)
@click.option(
    "-l",
    "--label-path",
    help="Path to file or directory of labeled netflow CSVs in NFStream format",
    default="labeled_nfstream_csvs",
)
@click.option(
    "-o",
    "--output-path",
    help="Directory path for output",
    default="labeled_nfstream_packets",
)
@click.option(
    "-c",
    "--cores",
    type=int,
    help="Number of cores to use; -1 to use all available",
    default=-1,
)
def main(input_path, label_path, output_path, cores):
    input_pcaps = gather_files(input_path)
    label_files = gather_files(label_path)

    csv_file_pairs = []  # matched label file to nfstream csvs
    for pcap_file in input_pcaps:
        day = os.path.split(pcap_file)[-1].split("-")[0]
        for label_file in label_files:
            if day in label_file:
                csv_file_pairs.append((pcap_file, label_file))

    os.makedirs(output_path, exist_ok=True)

    eth = Ethernet()

    if cores == 0:
        raise ValueError("cores must be -1 or positive integer")
    elif cores == -1:
        cpu_cores = mp.cpu_count() - 1
    else:
        cpu_cores = min(cores, mp.cpu_count() - 1)

    for (pcap_file, csv_file) in csv_file_pairs:
        print(f"Analyzing {pcap_file} using {csv_file}...")
        print("Reading CSV into dataframe")
        label_df = pd.read_csv(csv_file, delimiter="\t")
        print("Completed")
        malicious_label_df = label_df.loc[label_df["label"] != "benign"]
        unique_flow_keys = list(set(malicious_label_df["flow_id"].unique()))
        flow_extents = malicious_label_df[["bidirectional_first_seen_ms", "bidirectional_last_seen_ms"]].to_numpy()
        label_array = malicious_label_df["label"].to_numpy()

        chunk_size = int(np.ceil(len(unique_flow_keys) / cpu_cores))
        flow_key_arrs = [unique_flow_keys[idx * chunk_size: (idx + 1) * chunk_size] for idx in range(cpu_cores)]

        def _get_flow_times_labels(unique_flow_keys, flow_dict, flow_extents, label_array):
            for flow_id in unique_flow_keys:
                flow_id_mask = malicious_label_df["flow_id"] == flow_id
                flow_dict[flow_id] = {
                    "timings": flow_extents[flow_id_mask],
                    "labels": label_array[flow_id_mask],
                }

        # flow_dict = {}
        flow_dict = mp.Manager().dict()
        procs = [mp.Process(
            target=_get_flow_times_labels,
            args=(unique_keys, flow_dict, flow_extents, label_array)) for unique_keys in flow_key_arrs
        ]
        start_time = time.time()
        for p in procs:
            p.start()

        for p in procs:
            p.join()
        end_time = time.time()
        print(f"Finished indexing flows in {round(end_time - start_time, 3)} seconds")
        total_packet_count = label_df["bidirectional_packets"].sum()
        results_arr = []
        flow_dict = dict(flow_dict)
        with open(pcap_file, "rb") as pcap_handle:
            pcap_reader = UniversalReader(pcap_handle)
            for idx, (ts, buf) in tqdm(
                    enumerate(pcap_reader),
                    total=total_packet_count,
                    desc="Reading PCAP file"
            ):
                results_arr.append((idx, "benign"))

                try:
                    eth.unpack(buf)
                except Exception:
                    continue

                if not isinstance(eth.data, IP):
                    continue

                ip_pdu = eth.data

                if not isinstance(ip_pdu.data, (TCP, UDP)):
                    continue

                transport_pdu = ip_pdu.data

                flow_key_src2dst = "-".join(
                    [str(val) for val in (
                        ip_to_str(ip_pdu.src),
                        ip_to_str(ip_pdu.dst),
                        transport_pdu.sport,
                        transport_pdu.dport,
                        ip_pdu.p,
                    )
                    ]
                )

                flow_key_dst2src = "-".join(
                    [str(val) for val in (
                        ip_to_str(ip_pdu.dst),
                        ip_to_str(ip_pdu.src),
                        transport_pdu.dport,
                        transport_pdu.sport,
                        ip_pdu.p,
                    )
                    ]
                )

                flow_key = None
                if flow_key_src2dst in flow_dict:
                    flow_key = flow_key_src2dst
                elif flow_key_dst2src in flow_dict:
                    flow_key = flow_key_dst2src
                else:
                    continue

                timestamp = ts * 1000.0  # multiply to get milliseconds
                timing_arr = flow_dict[flow_key]["timings"]
                timing_mask_start = timing_arr[:, 0] <= timestamp
                timing_mask_end = timestamp <= timing_arr[:, 1]
                timing_mask = timing_mask_start & timing_mask_end
                if not np.any(timing_mask):
                    continue

                flow_labels = flow_dict[flow_key]["labels"][timing_mask]
                if len(np.unique(flow_labels)) > 1:
                    raise ValueError("unique flow label cannot be determined")

                results_arr[-1] = (idx, flow_labels[0])

        csv_file_name = os.path.split(pcap_file)[-1].replace(".pcap", ".csv")
        output_csv_path = os.path.join(output_path, csv_file_name)
        print(output_csv_path)
        with open(output_csv_path, "w") as output_handle:
            print(f"Writing output to {output_csv_path}")
            output_handle.write("index,label\n")
            for (idx, label) in tqdm(results_arr):
                string = f"{str(idx)},{label}\n"
                output_handle.write(string)


if __name__ == "__main__":
    main()
