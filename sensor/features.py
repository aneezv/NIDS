def parse_tshark_line(line):
    """
    Parses a single line of tshark CSV output.
    Format: ip.src, frame.len, tcp.dstport, udp.dstport, ip.proto, tcp.flags
    """
    try:
        parts = line.strip().split(',')
        if len(parts) < 6:
            return None, None

        src_ip = parts[0].strip().replace('\\', '').replace('"', '')
        if not src_ip:
            return None, None

        def p(v):
            try:
                # Handle empty strings or hex values
                if not v: return 0
                return int(v, 0)
            except:
                return 0

        # Smart Port Logic: Summing TCP and UDP ports as one will always be 0
        tcp_port = p(parts[2])
        udp_port = p(parts[3])
        actual_port = tcp_port + udp_port

        frame_len = p(parts[1])
        proto = p(parts[4])
        flags = p(parts[5])

        features = [frame_len, actual_port, proto, flags]
        return src_ip, features
    except Exception:
        return None, None
