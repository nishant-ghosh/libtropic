# 5. Separate API Example Tutorial
This example showcases the Libtropic's Separate API. It is functionally similar to the *Hello, World!* example, but it uses distinct API calls for incoming and outgoing data. This approach is useful for secure, tunneled communication, such as during chip provisioning in a factory.

!!! success "Prerequisites"
    It is assumed that you have already completed the previous TROPIC01 Model tutorials. If not, start [here](../model/index.md).

You will learn about some of the low-level API functions used to process outgoing and incoming data. For example:

- `lt_out__session_start()`: prepare Handshake_Req L2 request (for Secure Session establishment),
- `lt_l2_transfer()`: send L2 request and receive L2 response,
- `lt_in__session_start()`: process L2 response to the Handshake_Req.

## Build and Run
Before proceeding, make sure you have activated the virtual environment you installed the TROPIC01 Model in and started it. If you're lost, see [First Steps](first_steps.md).

Now, you can build and run the example:

!!! example "Building and running the example"
    === ":fontawesome-brands-linux: Linux"
        Go to the example's project directory:
        ```bash { .copy }
        cd examples/model/separate_api/
        ```
        Create a `build/` directory and switch to it:
        ```bash { .copy }
        mkdir build/
        cd build/
        ```
        And finally, build and run the example:
        ```bash { .copy }
        cmake ..
        make
        ./libtropic_separate_api
        ```

    === ":fontawesome-brands-apple: macOS"
        TBA

    === ":fontawesome-brands-windows: Windows"
        TBA

## Notes
While it is also possible to use `lt_l2_send` and `lt_l2_receive` pair for transferring L2 frames instead
of `lt_l2_transfer`, it is not recommended, as those functions do not implement retry mechanism on CRC
errors and do not increment CRC diagnostic counters. Prefer using `lt_l2_transfer`.