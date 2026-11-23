# Stage 5 packet evidence

Run: `evidence/captures/stage5/20261123T030641Z`. Generated from the real tshark field exports; pcapng files are private and contain disposable bearer tokens. Times are UTC. TCP stream numbers are local to each capture.

Install the wireshark_profile directory as a Wireshark profile via Edit > Configuration Profiles > Import, or copy it into the personal Wireshark profiles directory and select it. If decode-as entries do not load, use Analyze > Decode As and set TCP ports 8000 and 9000 to HTTP. The profile was checked with tshark; graphical Wireshark was not available.

In screenshots hide or mask Authorization values; leave raw pcapng files unchanged. For each selected packet annotate source/destination IP and ports, TTL, TCP flags, relative seq/ack, method/URI or status, request ID and X-Forwarded-For where present.

P-01 proves the proxy boundary. The request packets and tuples are in verification.csv. P1/P2/P3 show the same connection after successive routers; P4 is the gatewayÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢s independently originated connection. Captures of already-established connections need not include a handshake.

## P-01

Client output: `evidence/captures/stage5/20261123T030641Z/P-01/client.txt`.

- P1: `evidence/captures/stage5/20261123T030641Z/P-01/P1.pcapng`; 12 packets. Filter: `tcp.port == 8000`. Request frames ['4'], response frames ['8'], SYN frames ['1', '2'], FIN frames ['10', '11']. Screenshot suggestion: `evidence/screenshots/P-01-P1-exchange.png`. Inspect the listed frames and packet details; see the matching summary CSV.
- P2: `evidence/captures/stage5/20261123T030641Z/P-01/P2.pcapng`; 12 packets. Filter: `tcp.port == 8000`. Request frames ['4'], response frames ['8'], SYN frames ['1', '2'], FIN frames ['10', '11']. Screenshot suggestion: `evidence/screenshots/P-01-P2-exchange.png`. Inspect the listed frames and packet details; see the matching summary CSV.
- P3: `evidence/captures/stage5/20261123T030641Z/P-01/P3.pcapng`; 12 packets. Filter: `tcp.port == 8000`. Request frames ['4'], response frames ['8'], SYN frames ['1', '2'], FIN frames ['10', '11']. Screenshot suggestion: `evidence/screenshots/P-01-P3-exchange.png`. Inspect the listed frames and packet details; see the matching summary CSV.
- P4: `evidence/captures/stage5/20261123T030641Z/P-01/P4.pcapng`; 9 packets. Filter: `tcp.port == 9000`. Request frames ['4'], response frames ['8'], SYN frames ['1', '2'], FIN frames []. Screenshot suggestion: `evidence/screenshots/P-01-P4-exchange.png`. Inspect the listed frames and packet details; see the matching summary CSV.

## P-02

Client output: `evidence/captures/stage5/20261123T030641Z/P-02/client.txt`.

- P1: `evidence/captures/stage5/20261123T030641Z/P-02/P1.pcapng`; 12 packets. Filter: `tcp.port == 8000`. Request frames ['4'], response frames ['8'], SYN frames ['1', '2'], FIN frames ['10', '11']. Screenshot suggestion: `evidence/screenshots/P-02-P1-exchange.png`. Inspect the listed frames and packet details; see the matching summary CSV.
- P2: `evidence/captures/stage5/20261123T030641Z/P-02/P2.pcapng`; 12 packets. Filter: `tcp.port == 8000`. Request frames ['4'], response frames ['8'], SYN frames ['1', '2'], FIN frames ['10', '11']. Screenshot suggestion: `evidence/screenshots/P-02-P2-exchange.png`. Inspect the listed frames and packet details; see the matching summary CSV.
- P3: `evidence/captures/stage5/20261123T030641Z/P-02/P3.pcapng`; 12 packets. Filter: `tcp.port == 8000`. Request frames ['4'], response frames ['8'], SYN frames ['1', '2'], FIN frames ['10', '11']. Screenshot suggestion: `evidence/screenshots/P-02-P3-exchange.png`. Inspect the listed frames and packet details; see the matching summary CSV.
- P4: `evidence/captures/stage5/20261123T030641Z/P-02/P4.pcapng`; 13 packets. Filter: `tcp.port == 9000`. Request frames ['8'], response frames ['12'], SYN frames ['3', '4'], FIN frames ['1']. Screenshot suggestion: `evidence/screenshots/P-02-P4-exchange.png`. Inspect the listed frames and packet details; see the matching summary CSV.

## P-03

Client output: `evidence/captures/stage5/20261123T030641Z/P-03/client.txt`.

- P1: `evidence/captures/stage5/20261123T030641Z/P-03/P1.pcapng`; 12 packets. Filter: `tcp.port == 8000`. Request frames ['4'], response frames ['8'], SYN frames ['1', '2'], FIN frames ['10', '11']. Screenshot suggestion: `evidence/screenshots/P-03-P1-exchange.png`. Inspect the listed frames and packet details; see the matching summary CSV.
- P2: `evidence/captures/stage5/20261123T030641Z/P-03/P2.pcapng`; 12 packets. Filter: `tcp.port == 8000`. Request frames ['4'], response frames ['8'], SYN frames ['1', '2'], FIN frames ['10', '11']. Screenshot suggestion: `evidence/screenshots/P-03-P2-exchange.png`. Inspect the listed frames and packet details; see the matching summary CSV.
- P3: `evidence/captures/stage5/20261123T030641Z/P-03/P3.pcapng`; 12 packets. Filter: `tcp.port == 8000`. Request frames ['4'], response frames ['8'], SYN frames ['1', '2'], FIN frames ['10', '11']. Screenshot suggestion: `evidence/screenshots/P-03-P3-exchange.png`. Inspect the listed frames and packet details; see the matching summary CSV.
- P4: `evidence/captures/stage5/20261123T030641Z/P-03/P4.pcapng`; 0 packets. Filter: `tcp.port == 9000`. Request frames [], response frames [], SYN frames [], FIN frames []. Screenshot suggestion: `evidence/screenshots/P-03-P4-exchange.png`. No packets were captured at this point.

## P-04

Client output: `evidence/captures/stage5/20261123T030641Z/P-04/client.txt`.

- P1: `evidence/captures/stage5/20261123T030641Z/P-04/P1.pcapng`; 12 packets. Filter: `tcp.port == 8000`. Request frames ['4'], response frames ['8'], SYN frames ['1', '2'], FIN frames ['10', '11']. Screenshot suggestion: `evidence/screenshots/P-04-P1-exchange.png`. Inspect the listed frames and packet details; see the matching summary CSV.
- P2: `evidence/captures/stage5/20261123T030641Z/P-04/P2.pcapng`; 12 packets. Filter: `tcp.port == 8000`. Request frames ['4'], response frames ['8'], SYN frames ['1', '2'], FIN frames ['10', '11']. Screenshot suggestion: `evidence/screenshots/P-04-P2-exchange.png`. Inspect the listed frames and packet details; see the matching summary CSV.
- P3: `evidence/captures/stage5/20261123T030641Z/P-04/P3.pcapng`; 12 packets. Filter: `tcp.port == 8000`. Request frames ['4'], response frames ['8'], SYN frames ['1', '2'], FIN frames ['10', '11']. Screenshot suggestion: `evidence/screenshots/P-04-P3-exchange.png`. Inspect the listed frames and packet details; see the matching summary CSV.
- P4: `evidence/captures/stage5/20261123T030641Z/P-04/P4.pcapng`; 0 packets. Filter: `tcp.port == 9000`. Request frames [], response frames [], SYN frames [], FIN frames []. Screenshot suggestion: `evidence/screenshots/P-04-P4-exchange.png`. No packets were captured at this point.

## P-05

Client output: `evidence/captures/stage5/20261123T030641Z/P-05/client.txt`.

- P1: `evidence/captures/stage5/20261123T030641Z/P-05/P1.pcapng`; 12 packets. Filter: `tcp.port == 8000`. Request frames ['4'], response frames ['8'], SYN frames ['1', '2'], FIN frames ['10', '11']. Screenshot suggestion: `evidence/screenshots/P-05-P1-exchange.png`. Inspect the listed frames and packet details; see the matching summary CSV.
- P2: `evidence/captures/stage5/20261123T030641Z/P-05/P2.pcapng`; 12 packets. Filter: `tcp.port == 8000`. Request frames ['4'], response frames ['8'], SYN frames ['1', '2'], FIN frames ['10', '11']. Screenshot suggestion: `evidence/screenshots/P-05-P2-exchange.png`. Inspect the listed frames and packet details; see the matching summary CSV.
- P3: `evidence/captures/stage5/20261123T030641Z/P-05/P3.pcapng`; 12 packets. Filter: `tcp.port == 8000`. Request frames ['4'], response frames ['8'], SYN frames ['1', '2'], FIN frames ['10', '11']. Screenshot suggestion: `evidence/screenshots/P-05-P3-exchange.png`. Inspect the listed frames and packet details; see the matching summary CSV.
- P4: `evidence/captures/stage5/20261123T030641Z/P-05/P4.pcapng`; 0 packets. Filter: `tcp.port == 9000`. Request frames [], response frames [], SYN frames [], FIN frames []. Screenshot suggestion: `evidence/screenshots/P-05-P4-exchange.png`. No packets were captured at this point.

## P-06

Client output: `evidence/captures/stage5/20261123T030641Z/P-06/client.txt`.

- P1: `evidence/captures/stage5/20261123T030641Z/P-06/P1.pcapng`; 12 packets. Filter: `tcp.port == 8000`. Request frames ['4'], response frames ['8'], SYN frames ['1', '2'], FIN frames ['10', '11']. Screenshot suggestion: `evidence/screenshots/P-06-P1-exchange.png`. Inspect the listed frames and packet details; see the matching summary CSV.
- P2: `evidence/captures/stage5/20261123T030641Z/P-06/P2.pcapng`; 12 packets. Filter: `tcp.port == 8000`. Request frames ['4'], response frames ['8'], SYN frames ['1', '2'], FIN frames ['10', '11']. Screenshot suggestion: `evidence/screenshots/P-06-P2-exchange.png`. Inspect the listed frames and packet details; see the matching summary CSV.
- P3: `evidence/captures/stage5/20261123T030641Z/P-06/P3.pcapng`; 12 packets. Filter: `tcp.port == 8000`. Request frames ['4'], response frames ['8'], SYN frames ['1', '2'], FIN frames ['10', '11']. Screenshot suggestion: `evidence/screenshots/P-06-P3-exchange.png`. Inspect the listed frames and packet details; see the matching summary CSV.
- P4: `evidence/captures/stage5/20261123T030641Z/P-06/P4.pcapng`; 0 packets. Filter: `tcp.port == 9000`. Request frames [], response frames [], SYN frames [], FIN frames []. Screenshot suggestion: `evidence/screenshots/P-06-P4-exchange.png`. No packets were captured at this point.

## P-07

Client output: `evidence/captures/stage5/20261123T030641Z/P-07/client.txt`.

- P1: `evidence/captures/stage5/20261123T030641Z/P-07/P1.pcapng`; 252 packets. Filter: `tcp.port == 8000`. Request frames ['4', '16', '28', '40', '52', '64', '76', '88', '100', '112', '124', '136', '148', '160', '172', '184', '196', '208', '220', '232', '244'], response frames ['8', '20', '32', '44', '56', '68', '80', '92', '104', '116', '128', '140', '152', '164', '176', '188', '200', '212', '224', '236', '248'], SYN frames ['1', '2', '13', '14', '25', '26', '37', '38', '49', '50', '61', '62', '73', '74', '85', '86', '97', '98', '109', '110', '121', '122', '133', '134', '145', '146', '157', '158', '169', '170', '181', '182', '193', '194', '205', '206', '217', '218', '229', '230', '241', '242'], FIN frames ['10', '11', '22', '23', '34', '35', '46', '47', '58', '59', '70', '71', '82', '83', '94', '95', '106', '107', '118', '119', '130', '131', '142', '143', '154', '155', '166', '167', '178', '179', '190', '191', '202', '203', '214', '215', '226', '227', '238', '239', '250', '251']. Screenshot suggestion: `evidence/screenshots/P-07-P1-exchange.png`. Inspect the listed frames and packet details; see the matching summary CSV.
- P2: `evidence/captures/stage5/20261123T030641Z/P-07/P2.pcapng`; 252 packets. Filter: `tcp.port == 8000`. Request frames ['4', '16', '28', '40', '52', '64', '76', '88', '100', '112', '124', '136', '148', '160', '172', '184', '196', '208', '220', '232', '244'], response frames ['8', '20', '32', '44', '56', '68', '80', '92', '104', '116', '128', '140', '152', '164', '176', '188', '200', '212', '224', '236', '248'], SYN frames ['1', '2', '13', '14', '25', '26', '37', '38', '49', '50', '61', '62', '73', '74', '85', '86', '97', '98', '109', '110', '121', '122', '133', '134', '145', '146', '157', '158', '169', '170', '181', '182', '193', '194', '205', '206', '217', '218', '229', '230', '241', '242'], FIN frames ['10', '11', '22', '23', '34', '35', '46', '47', '58', '59', '70', '71', '82', '83', '94', '95', '106', '107', '118', '119', '130', '131', '142', '143', '154', '155', '166', '167', '178', '179', '190', '191', '202', '203', '214', '215', '226', '227', '238', '239', '250', '251']. Screenshot suggestion: `evidence/screenshots/P-07-P2-exchange.png`. Inspect the listed frames and packet details; see the matching summary CSV.
- P3: `evidence/captures/stage5/20261123T030641Z/P-07/P3.pcapng`; 252 packets. Filter: `tcp.port == 8000`. Request frames ['4', '16', '28', '40', '52', '64', '76', '88', '100', '112', '124', '136', '148', '160', '172', '184', '196', '208', '220', '232', '244'], response frames ['8', '20', '32', '44', '56', '68', '80', '92', '104', '116', '128', '140', '152', '164', '176', '188', '200', '212', '224', '236', '248'], SYN frames ['1', '2', '13', '14', '25', '26', '37', '38', '49', '50', '61', '62', '73', '74', '85', '86', '97', '98', '109', '110', '121', '122', '133', '134', '145', '146', '157', '158', '169', '170', '181', '182', '193', '194', '205', '206', '217', '218', '229', '230', '241', '242'], FIN frames ['10', '11', '22', '23', '34', '35', '46', '47', '58', '59', '70', '71', '82', '83', '94', '95', '106', '107', '118', '119', '130', '131', '142', '143', '154', '155', '166', '167', '178', '179', '190', '191', '202', '203', '214', '215', '226', '227', '238', '239', '250', '251']. Screenshot suggestion: `evidence/screenshots/P-07-P3-exchange.png`. Inspect the listed frames and packet details; see the matching summary CSV.
- P4: `evidence/captures/stage5/20261123T030641Z/P-07/P4.pcapng`; 89 packets. Filter: `tcp.port == 9000`. Request frames ['6', '12', '17', '22', '26', '30', '34', '38', '42', '46', '50', '54', '58', '62', '66', '70', '74', '78', '82', '86'], response frames ['10', '15', '20', '24', '28', '32', '36', '40', '44', '48', '52', '56', '60', '64', '68', '72', '76', '80', '84', '88'], SYN frames ['3', '4'], FIN frames ['1']. Screenshot suggestion: `evidence/screenshots/P-07-P4-exchange.png`. Inspect the listed frames and packet details; see the matching summary CSV.

## P-08

Client output: `evidence/captures/stage5/20261123T030641Z/P-08/client.txt`.

- P1: `evidence/captures/stage5/20261123T030641Z/P-08/P1.pcapng`; 12 packets. Filter: `tcp.port == 8000`. Request frames ['4'], response frames ['8'], SYN frames ['1', '2'], FIN frames ['10', '11']. Screenshot suggestion: `evidence/screenshots/P-08-P1-exchange.png`. Inspect the listed frames and packet details; see the matching summary CSV.
- P2: `evidence/captures/stage5/20261123T030641Z/P-08/P2.pcapng`; 12 packets. Filter: `tcp.port == 8000`. Request frames ['4'], response frames ['8'], SYN frames ['1', '2'], FIN frames ['10', '11']. Screenshot suggestion: `evidence/screenshots/P-08-P2-exchange.png`. Inspect the listed frames and packet details; see the matching summary CSV.
- P3: `evidence/captures/stage5/20261123T030641Z/P-08/P3.pcapng`; 12 packets. Filter: `tcp.port == 8000`. Request frames ['4'], response frames ['8'], SYN frames ['1', '2'], FIN frames ['10', '11']. Screenshot suggestion: `evidence/screenshots/P-08-P3-exchange.png`. Inspect the listed frames and packet details; see the matching summary CSV.
- P4: `evidence/captures/stage5/20261123T030641Z/P-08/P4.pcapng`; 0 packets. Filter: `tcp.port == 9000`. Request frames [], response frames [], SYN frames [], FIN frames []. Screenshot suggestion: `evidence/screenshots/P-08-P4-exchange.png`. No packets were captured at this point.

## P-09

Client output: `evidence/captures/stage5/20261123T030641Z/P-09/client.txt`.

- P1: `evidence/captures/stage5/20261123T030641Z/P-09/P1.pcapng`; 4 packets. Filter: `icmp || tcp.port == 9000`. Request frames [], response frames [], SYN frames ['3', '4'], FIN frames []. Screenshot suggestion: `evidence/screenshots/P-09-P1-exchange.png`. Inspect the listed frames and packet details; see the matching summary CSV.
- P2: `evidence/captures/stage5/20261123T030641Z/P-09/P2.pcapng`; 0 packets. Filter: `icmp || tcp.port == 9000`. Request frames [], response frames [], SYN frames [], FIN frames []. Screenshot suggestion: `evidence/screenshots/P-09-P2-exchange.png`. No packets were captured at this point.
- P3: `evidence/captures/stage5/20261123T030641Z/P-09/P3.pcapng`; 0 packets. Filter: `icmp || tcp.port == 9000`. Request frames [], response frames [], SYN frames [], FIN frames []. Screenshot suggestion: `evidence/screenshots/P-09-P3-exchange.png`. No packets were captured at this point.
- P4: `evidence/captures/stage5/20261123T030641Z/P-09/P4.pcapng`; 0 packets. Filter: `icmp || tcp.port == 9000`. Request frames [], response frames [], SYN frames [], FIN frames []. Screenshot suggestion: `evidence/screenshots/P-09-P4-exchange.png`. No packets were captured at this point.

## P-10

Client output: `evidence/captures/stage5/20261123T030641Z/P-10/client.txt`.

- P1: `evidence/captures/stage5/20261123T030641Z/P-10/P1.pcapng`; 16 packets. Filter: `tcp.port == 8000`. Request frames ['4', '10'], response frames ['8', '12'], SYN frames ['1', '2'], FIN frames ['14', '15']. Screenshot suggestion: `evidence/screenshots/P-10-P1-exchange.png`. Inspect the listed frames and packet details; see the matching summary CSV.
- P2: `evidence/captures/stage5/20261123T030641Z/P-10/P2.pcapng`; 16 packets. Filter: `tcp.port == 8000`. Request frames ['4', '10'], response frames ['8', '12'], SYN frames ['1', '2'], FIN frames ['14', '15']. Screenshot suggestion: `evidence/screenshots/P-10-P2-exchange.png`. Inspect the listed frames and packet details; see the matching summary CSV.
- P3: `evidence/captures/stage5/20261123T030641Z/P-10/P3.pcapng`; 16 packets. Filter: `tcp.port == 8000`. Request frames ['4', '10'], response frames ['8', '12'], SYN frames ['1', '2'], FIN frames ['14', '15']. Screenshot suggestion: `evidence/screenshots/P-10-P3-exchange.png`. Inspect the listed frames and packet details; see the matching summary CSV.
- P4: `evidence/captures/stage5/20261123T030641Z/P-10/P4.pcapng`; 15 packets. Filter: `tcp.port == 9000`. Request frames ['6', '12'], response frames ['10', '14'], SYN frames ['3', '4'], FIN frames ['1']. Screenshot suggestion: `evidence/screenshots/P-10-P4-exchange.png`. Inspect the listed frames and packet details; see the matching summary CSV.

## Findings and limits

P-09: R1 (10.10.1.1) sent ICMP destination unreachable, type 3 code 0; P2ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â€šÂ¬Ã…â€œP4 contain no packets for the attempt.
P-07: the P4 capture contains the earlier successful burst requests; use the final 429 request ID to distinguish the rejected request. P-03 P4 contains a prior connection FIN/ACK, not an HTTP request for the rejected ID.
P-10 uses one request ID for two sequential requests; P4 request frames show the same stream and source port, demonstrating upstream connection reuse in this run.

P-01 handshake/teardown: use the SYN and FIN frame numbers above, and the accompanying CSV for the exact relative sequence and acknowledgement numbers. HTTP fields are visible only after TCP reassembly where required.
