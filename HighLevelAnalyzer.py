# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions
# Author :Niek Ilmer

from saleae.analyzers import (
    HighLevelAnalyzer,
    AnalyzerFrame,
    StringSetting,
    NumberSetting,
    ChoicesSetting,
)
from GTL_definitions import MSG_ID_dict, ERR_CODE_dict, gapm_operation_dict

# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    result_types = {
        "gtl": {
            "format": "Message ID: {{data.MSG_ID}}({{data.MSG_ID_decoded}}), Dest ID: {{data.DST_ID}}, Source ID: {{data.SRC_ID}}, Parameter length: {{data.PAR_LEN}}, Data: {{data.data}}"
        },
        "err": {"format": "Error: {{data.error_message}}"},
        "gapm_cmp": {
            "format": "Gapm complete event for {{data.gapm_operation}}, result: {{data.ERR_CODE}}"
        },
        "conn_req": {
            "format": "Connection request from {{data.BDADDR}}({{data.addr_type}}), connection handle {{data.conhdl}} with an interval of {{data.con_interval}}ms"
        },
        "GAPC_PARAM_UPDATE_REQ_IND": {
            "format": "Connection parameter update request. Min:{{data.con_interval_min}}ms max:{{data.con_interval_max}}ms latency: {{data.con_latency}} and supervision timeout: {{data.sup_to}}ms"
        },
    }

    def __init__(self):
        self.receive_buffer_pointer = 0
        self.receiveBuffer = []

        print("Dialog Semiconductor GTL interface decoder")

    def decode(self, frame: AnalyzerFrame):
        return_packet = False
        try:
            if (
                frame.start_time - self.startTime
                > (frame.end_time - frame.start_time) * 400
            ) and (self.receive_buffer_pointer > 0):
                tempMSG = AnalyzerFrame(
                    "err", self.startTime, frame.end_time, {"error_message": "Timeout"}
                )
                self.receive_buffer_pointer = 0
                return_packet = True
        except:
            pass

        uartbuffer = int(frame.data["data"][0])
        if (
            (self.receive_buffer_pointer == 0 and uartbuffer == 5)
            or self.receive_buffer_pointer > 0
            and (not "error" in frame.data)
        ):
            if self.receive_buffer_pointer == 0:
                self.startTime = frame.start_time  # capture the start
                self.receiveBuffer = [uartbuffer]
            else:
                self.receiveBuffer.append(uartbuffer)
            if (
                self.receive_buffer_pointer >= 8
            ):  # Byte 7 and 8 tell how big the message is
                MSG_ID = (
                    self.receiveBuffer[2] << 8 | self.receiveBuffer[1]
                )  # Extract the message ID from the message
                DST_ID = (
                    self.receiveBuffer[4] << 8 | self.receiveBuffer[3]
                )  # Extract the destination ID from the message
                SRC_ID = (
                    self.receiveBuffer[6] << 8 | self.receiveBuffer[5]
                )  # Extract the source ID from the message
                PAR_LEN = (
                    self.receiveBuffer[8] << 8 | self.receiveBuffer[7]
                )  # Extract the parameter length from the message
                if (
                    self.receive_buffer_pointer >= PAR_LEN + 8
                ):  # Check to see if the entire message has been received
                    if MSG_ID == 0x0D00:
                        ERR_CODE = self.receiveBuffer[10]
                        ERR_CODE_decoded = "unknown"
                        gapm_operation = self.receiveBuffer[9]
                        gapm_operation_decoded = "unknown"
                        try:
                            gapm_operation_decoded = list(gapm_operation_dict.keys())[
                                list(gapm_operation_dict.values()).index(gapm_operation)
                            ]
                        except ValueError:  # Unknown ID
                            pass
                        try:
                            ERR_CODE_decoded = list(ERR_CODE_dict.keys())[
                                list(ERR_CODE_dict.values()).index(ERR_CODE)
                            ]
                        except ValueError:  # Unknown ID
                            pass
                        tempMSG = AnalyzerFrame(
                            "gapm_cmp",
                            self.startTime,
                            frame.end_time,
                            {
                                "gapm_operation": gapm_operation_decoded,
                                "ERR_CODE": ERR_CODE_decoded,
                                "MSG_ID": hex(MSG_ID),
                                "DST_ID": hex(DST_ID),
                                "SRC_ID": hex(SRC_ID),
                                "PAR_LEN": hex(PAR_LEN),
                                "data": bytes(self.receiveBuffer[9:]),
                                "rawdata": bytes(self.receiveBuffer).hex(" "),
                            },
                        )
                    elif MSG_ID == 0x0E01:
                        conhdl = str(
                            self.receiveBuffer[10] << 8 | self.receiveBuffer[9]
                        )  # Extract the connection handle from the message
                        con_interval = str(
                            (self.receiveBuffer[12] << 8 | self.receiveBuffer[11])
                            * 1.25
                        )  # Extract the connection interval from the message
                        con_latency = str(
                            self.receiveBuffer[14] << 8 | self.receiveBuffer[13]
                        )  # Extract the connection latency from the message
                        sup_to = str(
                            (self.receiveBuffer[16] << 8 | self.receiveBuffer[15]) * 10
                        )  # Extract the supervision timeout from the message
                        addr_type = self.receiveBuffer[18]  # Extract the address type from the message
                        if addr_type == 0:
                            addr_type = "public"
                        else:
                            addr_type = "random"
                        tempMSG = AnalyzerFrame(
                            "conn_req",
                            self.startTime,
                            frame.end_time,
                            {
                                "addr_type": addr_type,
                                "sup_to": sup_to,
                                "con_latency": con_latency,
                                "con_interval": con_interval,
                                "conhdl": conhdl,
                                "BDADDR": bytes(self.receiveBuffer[-1:18:-1]).hex(":"),
                                "MSG_ID": hex(MSG_ID),
                                "DST_ID": hex(DST_ID),
                                "SRC_ID": hex(SRC_ID),
                                "PAR_LEN": hex(PAR_LEN),
                                "data": bytes(self.receiveBuffer[9:]),
                                "rawdata": bytes(self.receiveBuffer).hex(" "),
                            },
                        )
                    elif MSG_ID == 0x0E0F:
                        con_interval_min = str(
                            (self.receiveBuffer[10] << 8 | self.receiveBuffer[9]) * 1.25
                        )  # Extract the min connection interval from the message
                        con_interval_max = str(
                            (self.receiveBuffer[12] << 8 | self.receiveBuffer[11]) * 1.25
                        )  # Extract the max connection interval from the message
                        con_latency = str(
                            self.receiveBuffer[14] << 8 | self.receiveBuffer[13]
                        )  # Extract the connection latency from the message
                        sup_to = str(
                            (self.receiveBuffer[16] << 8 | self.receiveBuffer[15]) * 10
                        )  # Extract the supervision timeout from the message
                        tempMSG = AnalyzerFrame(
                            "GAPC_PARAM_UPDATE_REQ_IND",
                            self.startTime,
                            frame.end_time,
                            {
                                "con_interval_min": con_interval_min,
                                "sup_to": sup_to,
                                "con_latency": con_latency,
                                "con_interval_max": con_interval_max,
                                "MSG_ID": hex(MSG_ID),
                                "DST_ID": hex(DST_ID),
                                "SRC_ID": hex(SRC_ID),
                                "PAR_LEN": hex(PAR_LEN),
                                "data": bytes(self.receiveBuffer[9:]),
                                "rawdata": bytes(self.receiveBuffer).hex(" "),
                            },
                        )
                    else:
                        MSG_ID_decoded = "unknown"
                        try:
                            MSG_ID_decoded = list(MSG_ID_dict.keys())[
                                list(MSG_ID_dict.values()).index(MSG_ID)
                            ]
                        except ValueError:  # Unknown ID
                            pass
                        tempMSG = AnalyzerFrame(
                            "gtl",
                            self.startTime,
                            frame.end_time,
                            {
                                "MSG_ID": hex(MSG_ID),
                                "DST_ID": hex(DST_ID),
                                "SRC_ID": hex(SRC_ID),
                                "PAR_LEN": hex(PAR_LEN),
                                "data": bytes(self.receiveBuffer[9:]),
                                "rawdata": bytes(self.receiveBuffer).hex(" "),
                                "MSG_ID_decoded": MSG_ID_decoded,
                            },
                        )
                    self.receive_buffer_pointer = -1
            self.receive_buffer_pointer += 1
            if self.receive_buffer_pointer == 0:
                return tempMSG
        if return_packet:
            return tempMSG
