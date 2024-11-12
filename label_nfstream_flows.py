import click
import nfstream as nf
import nfstream
import numba as nb
import numpy as np
import pandas as pd
from pandas.errors import SettingWithCopyWarning
import os
import time
import warnings

from utils import gather_files


warnings.simplefilter(action="ignore", category=SettingWithCopyWarning)


CIC_FLOW_METER_LOCAL_TIME_OFFSET = 3  # hours


@nb.njit
def compare_timestamps(cic_flows, nf_flows):
    ret_arr = np.zeros(nf_flows.shape[0], dtype=np.int64)
    min_start = cic_flows[:, 0].min()
    max_end = cic_flows[:, 1].max()
    for i in range(nf_flows.shape[0]):
        ret_arr[i] = (
            (nf_flows[i, 0] >= min_start) & (nf_flows[i, 1] <= max_end) &
            (cic_flows[:, 0] <= nf_flows[i, 0]) | (cic_flows[:, 1] >= nf_flows[i, 1])
        ).sum() > 0

    return ret_arr


@click.command()
@click.option(
    "-i",
    "--input-path",
    help="Path to input file or directory of CSVs to map",
    default="deduped",
)
@click.option(
    "-l",
    "--label-path",
    help="Path to file or directory of labeled netflow CSVs in CICFlowMeter format",
    default="crisis2022/Labels/Exp_RP/",
)
@click.option(
    "-n",
    "--nfstream-path",
    help="Path to output NFStream CSVs",
    default="nfstream_csvs",
)
@click.option(
    "-o",
    "--output-path",
    help="Directory path for output",
    default="labeled_nfstream_csvs",
)
@click.option(
    "-f",
    "--force",
    help="Force PCAP analysis to occur if CSV already exists",
    is_flag=True,
    default=False,
)
@click.option(
    "--active-timeout",
    help="Duration flows can stay active in seconds",
    default=120,
    type=int,
)
@click.option(
    "--idle-timeout",
    help="Duration flows may remain inactive before termination",
    default=6,
    type=int,
)
@click.option(
    "--epsilon",
    help="Value by which CICFlowMeter flows are widened in seconds due to initial rounding",
    default=0.5,
    type=float,
)
def main(
    input_path,
    label_path,
    nfstream_path,
    output_path,
    force,
    active_timeout,
    idle_timeout,
    epsilon,
):
    input_pcaps = gather_files(input_path)
    label_files = gather_files(label_path)

    nfstream_csvs = []
    for pcap_file in input_pcaps:
        print(f"Analyzing {pcap_file}...")
        output_csv = os.path.split(pcap_file)[1].replace("pcap", "csv")
        output_csv_path = os.path.join(nfstream_path, output_csv)
        nfstream_csvs.append(output_csv_path)
        if os.path.exists(output_csv_path) and not force:
            print("CSV found! Passing.")
            continue

        streamer = nfstream.streamer.NFStreamer(
            pcap_file,
            statistical_analysis=True,
            active_timeout=active_timeout,
            idle_timeout=idle_timeout,
            n_meters=1,
            n_dissections=0,
            decode_tunnels=False,
        )
        start_time = time.time()
        streamer.to_csv(output_csv_path)
        end_time = time.time()
        print(
            f"Statistics written to {output_csv_path} in"
            + f" {round(end_time - start_time, 3)} seconds"
        )

    csv_file_pairs = []  # matched label file to nfstream csvs
    for nfs_csv in nfstream_csvs:
        day = os.path.split(nfs_csv)[-1].split("-")[0]
        for label_file in label_files:
            if day in label_file:
                csv_file_pairs.append((nfs_csv, label_file))

    os.makedirs(output_path, exist_ok=True)

    for nfs_csv, label_file in csv_file_pairs:
        print(f"Labeling {nfs_csv} using {label_file} as ground truth...")
        nf_df = pd.read_csv(nfs_csv)
        lf_df = pd.read_csv(label_file)
        nf_df["flow_id"] = [
            "-".join([str(val) for val in values])
            for values in zip(
                nf_df["src_ip"],
                nf_df["dst_ip"],
                nf_df["src_port"],
                nf_df["dst_port"],
                nf_df["protocol"],
            )
        ]
        nf_df["label"] = "benign"
        cic_date_fmt = "%d/%m/%Y %H:%M:%S"
        lf_df["cic_flow_start"] = (
            pd.to_datetime(lf_df["Timestamp"], format=cic_date_fmt)
            + pd.Timedelta(hours=CIC_FLOW_METER_LOCAL_TIME_OFFSET)
            - pd.Timedelta(seconds=epsilon)
        )
        lf_df["cic_flow_end"] = (
            pd.to_datetime(lf_df["Timestamp"], format=cic_date_fmt)
            + pd.Timedelta(
                hours=CIC_FLOW_METER_LOCAL_TIME_OFFSET,
                seconds=epsilon,
            )
            + pd.to_timedelta(lf_df["Flow Duration"], unit="us")
        )
        nf_df["flow_start"] = pd.to_datetime(
            nf_df["bidirectional_first_seen_ms"], unit="ms"
        )
        for label_name in lf_df["Label"].unique():
            print()
            print(label_name)
            label = label_name.lower()
            if label == "benign":
                continue

            cic_mal_flows = lf_df.loc[lf_df["Label"] == label_name]
            nf_mal_flows = nf_df.loc[
                nf_df["flow_id"].isin(cic_mal_flows["Flow ID"].unique())
            ]
            refined_nf_mal_flows = nf_mal_flows.loc[
                (cic_mal_flows["cic_flow_start"].min() <= nf_mal_flows["flow_start"])
                & (nf_mal_flows["flow_start"] <= cic_mal_flows["cic_flow_end"].max())
                # & (nf_mal_flows["bidirectional_packets"] > 2)
                # & (nf_mal_flows["bidirectional_duration_ms"] > 6)
            ]
            print("\tFlow totals:")
            print("\tCIC", len(cic_mal_flows))
            print("\tNFS", len(refined_nf_mal_flows))
            nf_df["label"].iloc[refined_nf_mal_flows.index] = label
            # cic_mal_flows["cic_flow_start_ms"] = (cic_mal_flows["cic_flow_start"] - pd.Timestamp("1970-01-01")).dt.total_seconds() * 1000.0
            # cic_mal_flows["cic_flow_end_ms"] = (cic_mal_flows["cic_flow_end"] - pd.Timestamp("1970-01-01")).dt.total_seconds() * 1000.0
            # cic_time_extents = cic_mal_flows[["cic_flow_start_ms", "cic_flow_end_ms"]].to_numpy()
            # nf_time_extents = nf_mal_flows[["bidirectional_first_seen_ms", "bidirectional_last_seen_ms"]].to_numpy()
            # valid_indices = compare_timestamps(cic_time_extents, nf_time_extents)
            # print(len(cic_mal_flows))
            # print(np.sum(valid_indices))
            # nf_df["label"].iloc[nf_mal_flows.index[valid_indices]] = label
            cic_total_packets = cic_mal_flows["Total Fwd Packet"].sum() + cic_mal_flows["Total Bwd packets"].sum()
            print("\tPacket totals:")
            print("\tCIC", cic_total_packets)
            nfs_total_packets = nf_df.loc[nf_df["label"] == label, "bidirectional_packets"].sum()
            print("\tNFS", nfs_total_packets)

        csv_name = os.path.split(nfs_csv)[-1]
        output_csv_with_labels = os.path.join(output_path, csv_name)
        print(f"Writing out labeled NFStream file {output_csv_with_labels}")
        nf_df.to_csv(output_csv_with_labels, sep="\t")


if __name__ == "__main__":
    main()
