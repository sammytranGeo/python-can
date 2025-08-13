#!/usr/bin/env python

import subprocess
import unittest
import can
from can.interfaces.socketcand import socketcand, SocketCanDaemonBus

from config import TEST_INTERFACE_SOCKETCAND


TEST_SOCKETCAND_HOST = "localhost"
TEST_SOCKETCAND_PORT = 29536
TEST_VCAN_IFACE = "vcan0"
TEST_SOCKETCAN_IFACE = "can_6_14"  # has to support bittiming and ctrlmode


class TestConvertAsciiMessageToCanMessage(unittest.TestCase):
    def test_valid_frame_message(self):
        # Example: < frame 123 1680000000.0 01020304 >
        ascii_msg = "< frame 123 1680000000.0 01020304 >"
        msg = socketcand.convert_ascii_message_to_can_message(ascii_msg)
        self.assertIsInstance(msg, can.Message)
        self.assertEqual(msg.arbitration_id, 0x123)
        self.assertEqual(msg.timestamp, 1680000000.0)
        self.assertEqual(msg.data, bytearray([1, 2, 3, 4]))
        self.assertEqual(msg.dlc, 4)
        self.assertFalse(msg.is_extended_id)
        self.assertTrue(msg.is_rx)

    def test_valid_error_message(self):
        # Example: < error 1ABCDEF0 1680000001.0 >
        ascii_msg = "< error 1ABCDEF0 1680000001.0 >"
        msg = socketcand.convert_ascii_message_to_can_message(ascii_msg)
        self.assertIsInstance(msg, can.Message)
        self.assertEqual(msg.arbitration_id, 0x1ABCDEF0)
        self.assertEqual(msg.timestamp, 1680000001.0)
        self.assertEqual(msg.data, bytearray([0]))
        self.assertEqual(msg.dlc, 1)
        self.assertTrue(msg.is_extended_id)
        self.assertTrue(msg.is_error_frame)
        self.assertTrue(msg.is_rx)

    def test_invalid_message(self):
        ascii_msg = "< unknown 123 0.0 >"
        msg = socketcand.convert_ascii_message_to_can_message(ascii_msg)
        self.assertIsNone(msg)

    def test_missing_ending_character(self):
        ascii_msg = "< frame 123 1680000000.0 01020304"
        msg = socketcand.convert_ascii_message_to_can_message(ascii_msg)
        self.assertIsNone(msg)


class SocketCanDaemonTest(unittest.TestCase):
    """
    Test class for the SocketCanDaemonBus interface.

    This class includes tests for creating a bus, setting bitrate, and configuring
    the bus. It uses a live socketcand process for testing.
    """

    socketcand_process = None  # Class attribute to hold the socketcand subprocess

    @classmethod
    def setUpClass(cls):
        """
        Set up the test class by starting the socketcand process.

        This method is called once before any tests in the class are run.
        It starts a socketcand process with a virtual CAN interface (vcan0)
        and a real CAN interface (can0) if TEST_INTERFACE_SOCKETCAND is True.
        """
        if not TEST_INTERFACE_SOCKETCAND:
            print(
                "TEST_INTERFACE_SOCKETCAN is false. "
                f"Skipping socketcand process startup for {cls.__name__}."
            )
            return

        try:
            # Start socketcand process with both vcan0 and can0 interfaces
            # pylint: disable=consider-using-with
            cls.socketcand_process = subprocess.Popen(
                [
                    "socketcand",
                    "-i",
                    f"{TEST_VCAN_IFACE},{TEST_SOCKETCAN_IFACE}",
                    "-p",
                    str(TEST_SOCKETCAND_PORT),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            if cls.socketcand_process.poll() is not None:
                # Process terminated prematurely, capture output for debugging
                stdout, stderr = cls.socketcand_process.communicate()
                print(
                    f"socketcand failed to start or terminated prematurely. "
                    f"Exit code: {cls.socketcand_process.returncode}. "
                    f"Ensure '{TEST_VCAN_IFACE}' and '{TEST_SOCKETCAN_IFACE}' "
                    "are up and socketcand is installed and configured correctly.\n"
                    f"Stdout: {stdout.decode(errors='ignore')}\n"
                    f"Stderr: {stderr.decode(errors='ignore')}"
                )
                cls.socketcand_process = None
        except FileNotFoundError:
            print("socketcand command not found. Please ensure it is installed and in PATH.")
            cls.socketcand_process = None
        except Exception as e:  # pylint: disable=broad-exception-caught
            print(f"An unexpected error occurred while starting socketcand: {e}")
            if cls.socketcand_process and hasattr(cls.socketcand_process, "terminate"):
                try:
                    cls.socketcand_process.stdout.close()
                    cls.socketcand_process.stderr.close()
                    cls.socketcand_process.terminate()
                    cls.socketcand_process.wait()

                except Exception:  # pylint: disable=broad-exception-caught
                    pass
            cls.socketcand_process = None

    @classmethod
    def tearDownClass(cls):
        """
        Tear down the test class by terminating the socketcand process.

        This method is called once after all tests in the class have been run.
        It ensures that the socketcand process is properly terminated.
        """
        if cls.socketcand_process:
            try:
                cls.socketcand_process.stdout.close()
                cls.socketcand_process.stderr.close()
                cls.socketcand_process.terminate()
                cls.socketcand_process.wait()  # Wait for graceful termination
            except subprocess.TimeoutExpired:
                print("socketcand did not terminate gracefully, killing.")
                cls.socketcand_process.kill()
                try:
                    cls.socketcand_process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    print("socketcand did not die even after kill.")
            except Exception as e:  # pylint: disable=broad-exception-caught
                print(f"Error terminating socketcand: {e}")
            finally:
                cls.socketcand_process = None

    def setUp(self):
        # This check runs before each test method.
        if not TEST_INTERFACE_SOCKETCAND:
            self.skipTest("TEST_INTERFACE_SOCKETCAND is false. Skipping test.")
        if not self.socketcand_process:
            self.skipTest("socketcand process is not running or failed to start. Skipping test.")

        # Check if socketcand process is still running before each test
        if self.socketcand_process.poll() is not None:
            stdout, stderr = self.socketcand_process.communicate()
            self.fail(
                f"socketcand process died unexpectedly before test execution. "
                f"Exit code: {self.socketcand_process.returncode}. "
                f"Stdout: {stdout.decode(errors='ignore')}\n"
                f"Stderr: {stderr.decode(errors='ignore')}"
            )

    @unittest.skipUnless(TEST_INTERFACE_SOCKETCAND, "Only run when vcan0 is available")
    def test_bus_creation(self):
        """Test that a SocketCanDaemonBus can be created and connects to the vcan0 interface."""
        bus = None
        try:
            bus = can.Bus(
                interface="socketcand",
                channel=f"{TEST_VCAN_IFACE}",
                host=TEST_SOCKETCAND_HOST,
                port=TEST_SOCKETCAND_PORT,
            )
            self.assertIsInstance(bus, SocketCanDaemonBus)
            self.assertIn(f"{TEST_VCAN_IFACE}", bus.channel_info)
        finally:
            if bus:
                bus.shutdown()

    @unittest.skipUnless(TEST_INTERFACE_SOCKETCAND, "Only run when can0 is available")
    def test_bitrate_setting(self):
        """
        Test that a SocketCanDaemonBus:
            - can be created
            - connects to the can0 interface
            - sets the bitrate.
        """
        bus = None
        try:
            bus = can.Bus(
                interface="socketcand",
                channel=f"{TEST_SOCKETCAN_IFACE}",
                host=TEST_SOCKETCAND_HOST,
                port=TEST_SOCKETCAND_PORT,
                bitrate=500000,
            )
            self.assertIsInstance(bus, SocketCanDaemonBus)
            self.assertIn(f"{TEST_SOCKETCAN_IFACE}", bus.channel_info)
            self.assertIn("bitrate=500000", bus.channel_info)
        finally:
            if bus:
                bus.shutdown()

    @unittest.skipUnless(TEST_INTERFACE_SOCKETCAND, "Only run when can0 is available")
    def test_config_setting(self):
        """
        Test that a SocketCanDaemonBus:
            - can be created
            - connects to the can0 interface
            - sets configuration options
        """
        bus = None
        try:
            bus = can.Bus(
                interface="socketcand",
                channel=f"{TEST_SOCKETCAN_IFACE}",
                host=TEST_SOCKETCAND_HOST,
                port=TEST_SOCKETCAND_PORT,
                config=True,
                listen_only=True,
            )
            self.assertIsInstance(bus, SocketCanDaemonBus)
            self.assertIn(f"{TEST_SOCKETCAN_IFACE}", bus.channel_info)
            self.assertIn("listen_only=True", bus.channel_info)
        finally:
            if bus:
                bus.shutdown()

if __name__ == "__main__":
    unittest.main()
