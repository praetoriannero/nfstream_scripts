import click
from dpkt.pcap import UniversalReader
from dpkt.ethernet import Ethernet
from dpkt.ip import IP
from dpkt.ip6 import IP6
from dpkt.tcp import TCP
from dpkt.udp import UDP
import os
import pandas as pd
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
    default="labeled_nfstream_pcaps",
)
def main(input_path, label_path, output_path):
    input_pcaps = gather_files(input_path)
    label_files = gather_files(label_path)

    csv_file_pairs = []  # matched label file to nfstream csvs
    for pcap_file in input_pcaps:
        day = os.path.split(pcap_file)[-1].split("-")[0]
        for label_file in label_files:
            if day in label_file:
                csv_file_pairs.append((pcap_file, label_file))

    print(csv_file_pairs)
    os.makedirs(output_path, exist_ok=True)

    eth = Ethernet()

    for (pcap_file, csv_file) in csv_file_pairs:
        label_df = pd.read_csv(csv_file, delimiter="\t")
        unique_labels = label_df["label"].unique()
        unique_flow_keys = set(label_df["flow_id"].unique())
        # nf_df["flow_start"] = pd.to_datetime(
        #     nf_df["bidirectional_first_seen_ms"], unit="ms"
        # )
        # nf_df["flow_start"] = pd.to_datetime(
        #     nf_df["bidirectional_first_seen_ms"], unit="ms"
        # )
        total_packet_count = 0
        with open(pcap_file, "rb") as pcap_handle:
            pcap_reader = UniversalReader(pcap_handle)
            for _ in tqdm(pcap_reader):
                total_packet_count += 1

            print(total_packet_count)

        with open(pcap_file, "rb") as pcap_handle:
            pcap_reader = UniversalReader(pcap_handle)
            labels = ["benign" for _ in range(total_packet_count)]

            for idx, (ts, buf) in tqdm(enumerate(pcap_reader), total=total_packet_count):
                try:
                    eth.unpack(buf)
                except:
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






if __name__ == "__main__":
    main()
