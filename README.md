# CCord
Low level Discord C library for interfacing with the Gateway and REST API.

I will start working on this library soon. It will be the basis for all my future Discord bots and my main focus is to get it production ready for Eris - my bot platform I'm currently working on.

The goal of this library is to provide very low level access to the Discord API which can then used as a base for more higher level libraries which provide more abstraction in C++ or native javascript modules for QuickJS and NodeJS.

# Initial Goals (Vision)
These are goals I'm setting for myself before I start with the project, so they might change if they're not possible with the existing API!
- [ ] Support V8 of the API
- [ ] Opt intents - only process what the specific use case requires.
- [ ] As little dependencies as possible - I'm currently thinking uv, llhttp, openssl, zlib, simdjson as only dependencies (with opus and ffmpeg for voice in future)
- [ ] Low memory - embeddable
- [ ] Fast - quick decompression, parsing and serializing of JSON.
- [ ] Caching as a opt in feature (maybe sqlite?)

## Higher level abstractions (Utilities)
- [ ] Embed builder
- [ ] Message parser (for commands)
- [ ] Handle timeout - Timeout thread if message isn't handled within set time
- [ ] Logger
