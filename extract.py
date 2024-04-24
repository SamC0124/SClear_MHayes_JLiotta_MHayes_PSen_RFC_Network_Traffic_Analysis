# Extracting Features File
# Authored by Joe Liotta and Samuel Clear

import pyshark
import numpy as np

# Temporary variable for Source's Local IP Address (Not Revealed in Output of Model)
source_ip = '10.245.207.45'

# Load the pcapng file
capture = pyshark.FileCapture('data/clear_cap.pcapng')

def get_stats(cap):
    flow_stats = {}

    for packet in cap:
        # Define a unique tuple for each flow
        try:
            flow_key = (packet.ip.src, packet.ip.dst, packet.tcp.srcport, packet.tcp.dstport)
        except AttributeError:
            continue
        # Initialize flow statistics if new flow
        if flow_key not in flow_stats:
            flow_stats[flow_key] = {
                'Flow Duration': float(0),
                'Total Fwd Packets': np.uint64(0),
                'Total Bwd Packets': np.uint64(0),
                'Bwd Init Win Bytes': np.uint64(0),
                'FWD Init Win Bytes': np.uint64(0),
                'Start Time': float(packet.sniff_timestamp)
            }
        # Update flow statistics
        stats = flow_stats[flow_key]
        stats['Flow Duration'] = float(packet.sniff_timestamp) - stats['Start Time']
        if packet.ip.src == flow_key[0]:  # Forward packet
            stats['Total Fwd Packets'] += 1
            if 'TCP' in packet and not stats['FWD Init Win Bytes']:
                stats['FWD Init Win Bytes'] = np.uint64(packet.tcp.window_size_value)
        elif packet.ip.dst == flow_key[1]:  # Backward packet
            stats['Total Bwd Packets'] += 1
            if 'TCP' in packet and not stats['Bwd Init Win Bytes']:
                stats['Bwd Init Win Bytes'] = np.uint64(packet.tcp.window_size_value)

    # Combine flows with the same source and destination, when copying from one
    # address to another fields are reversed
    combined = {}

    for flow_key, stats in flow_stats.items():
        # Check if the reverse flow exists
        reverse_flow_key = (flow_key[1], flow_key[0], flow_key[3], flow_key[2])
        if reverse_flow_key in flow_stats and reverse_flow_key not in combined:
            # Combine the two flows
            reverse_stats = flow_stats[reverse_flow_key]
            stats['Total Bwd Packets'] = reverse_stats['Total Fwd Packets']
            stats['Bwd Init Win Bytes'] = reverse_stats['FWD Init Win Bytes']
            # add the combined flow to the combined dictionary
            combined[flow_key] = stats

    final = {}
    # for flows where the destination ip is set to the source_ip variable flip the
    # source and destination as well as the ports and fwd/bwd byte counts
    for flow_key, stats in combined.items():
        if flow_key[1] == source_ip:
            reversed_flow_key = (flow_key[1], flow_key[0], flow_key[3], flow_key[2])
            final[reversed_flow_key] = {
                'Flow Duration': stats['Flow Duration'],
                'Total Fwd Packets': stats['Total Bwd Packets'],
                'Total Bwd Packets': stats['Total Fwd Packets'],
                'Bwd Init Win Bytes': stats['FWD Init Win Bytes'],
                'FWD Init Win Bytes': stats['Bwd Init Win Bytes'],
                'Start Time': stats['Start Time']
            }
        else:
            final[flow_key] = stats
    return combined

def main():
    fin = get_stats(capture)

    # Output the flow statistics to a csv file
    with open('darkNetTempSam.csv', 'w') as f:
        for flow, stats in fin.items():
            print(flow)
            f.write(f'{flow[0]},{flow[1]},{flow[2]},{flow[3]},')
            for stat_name, stat_value in stats.items():
                f.write(f'{stat_value},')
            f.write('\n')
    f.close()

    # Display the flow statistics
    for flow, stats in fin.items():
        print(f'Flow: {flow}')
        for stat_name, stat_value in stats.items():
            print(f'{stat_name}: {stat_value}')
        print()

if __name__ == "__main__":
    main() 
