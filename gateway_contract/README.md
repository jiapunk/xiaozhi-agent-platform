# Gateway Contract Reference

This directory is an executable, dependency-free reference for the server side
of `VOICE_AGENT_PROTOCOL.md`. It is not a production gateway and performs no
network, model, or TTS calls.

It defines the behavior a production implementation must preserve:

- exact Device Agent v1 hello acknowledgement;
- single-active-request lifecycle;
- session and request correlation;
- correlated `start`, `sentence_start`, `stop`, and `error` events;
- barge-in/abort cleanup;
- field types, sizes, and stable protocol-violation categories.

Run it directly with:

```sh
python3 -m unittest discover -s gateway_contract -p 'test_*.py'
```

When a production gateway stack is selected, port these cases to its native
test framework and run both implementations against shared JSON fixtures.
