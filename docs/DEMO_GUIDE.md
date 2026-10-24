# Presentation walkthrough

## Before the demonstration

Install dependencies and create the first administrator account using a Gmail address. Add your names, contributions, photos, portfolio links, and optional CVs in The Developers. Leave detection defaults unchanged for the bundled fixture. Keep any real credentials outside your presentation slides.

## A five minute presentation

1. **Problem:** Network traffic creates many observations; an analyst needs explainable signals and repeatable demonstrations.
2. **Overview:** Show ten separate navigation pages, switch between dark and light themes, and explain that counters come from stored packet records.
3. **Replay:** Load the guided demo, choose 4x or 8x, and start. Explain that replay never retransmits packets.
4. **Evidence:** Open a port-scan alert. Show source, destination, observed ports, window, threshold, and related packets.
5. **Triage:** Mark it Investigating and save a short explanation. Open the source host to connect alerts with its traffic.
6. **Analysis:** Show the capture-time chart, protocol distribution, top talkers, and rule breakdown.
7. **Configuration:** Explain configurable thresholds and why a session freezes its rule snapshot.
8. **Integration:** Import `samples/example-eve.json` to show an external signature-engine alert.
9. **Accounts and projects:** Show registration, private workspaces, administrator permissions, and both developers’ public GitHub repository cards.
10. **Engineering:** Briefly show the architecture diagram, tests, SRS, and GitHub README.
11. **Limits:** Explain that these are indicators rather than proof, encrypted content limits inspection, and live capture sees only available traffic.

## Questions to prepare for

- Why does increasing replay speed not change detector results?
- What distinguishes source/destination ports from source/destination IPs?
- Why can legitimate backups or DNS resolvers trigger alerts?
- Why is a SYN burst not proof of a successful denial of service?
- How does the application prevent captured strings from becoming HTML?
- What happens if capture permissions are missing or storage limits are reached?
- Which features are implemented, and which are future extensions?

Expected default fixture output: 501 packets and six alerts. The simple normal fixture contains 60 packets and produces no alerts. These results validate fixture behavior, not general detection accuracy.
