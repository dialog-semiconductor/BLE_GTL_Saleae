# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions
# Author :Niek Ilmer

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    #my_string_setting = StringSetting()
    #my_number_setting = NumberSetting(min_value=0, max_value=100)
    #my_choices_setting = ChoicesSetting(choices=('A', 'B'))

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'gtl': {
            'format': 'Message ID: {{data.MSG_ID}}, Dest ID: {{data.DST_ID}}, Source ID: {{data.SRC_ID}}, Parameter length: {{data.PAR_LEN}}, Data: {{data.data}}'
        },
        'error': {
            'format': 'Error: {{data.error}}}'
        }
    }

    def __init__(self):
        '''
        Initialize HLA.
        
        Settings can be accessed using the same name used above.
        '''
        self.receive_buffer_pointer = 0;
        self.receiveBuffer = [];
   
        print("Dialog Semiconductor GTL interface decoder by Niek Ilmer")

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''
        uartbuffer = int(frame.data['data'][0])
        if (( self.receive_buffer_pointer == 0 and uartbuffer == 5) or self.receive_buffer_pointer > 0 and (not 'error' in frame.data)):
            if self.receive_buffer_pointer == 0:
                self.startTime = frame.start_time #capture the start
                self.receiveBuffer = [uartbuffer]; 
            else:
                self.receiveBuffer.append(uartbuffer);
            if(self.receive_buffer_pointer >= 8):#Byte 7 and 8 tell how big the message is
                MSG_ID = self.receiveBuffer[2] << 8 | self.receiveBuffer[1]; #Extract the parameter length from the message
                DST_ID = self.receiveBuffer[4] << 8 | self.receiveBuffer[3]; #Extract the parameter length from the message
                SRC_ID = self.receiveBuffer[6] << 8 | self.receiveBuffer[5]; #Extract the parameter length from the message
                PAR_LEN = self.receiveBuffer[8] << 8 | self.receiveBuffer[7]; #Extract the parameter length from the message
                if ( self.receive_buffer_pointer >= PAR_LEN + 8): #Check to see if the entire message has been received
                    tempMSG = AnalyzerFrame('gtl', self.startTime, frame.end_time, {'MSG_ID': hex(MSG_ID),'DST_ID': hex(DST_ID),'SRC_ID': hex(SRC_ID),'PAR_LEN': (PAR_LEN),'data': bytes(self.receiveBuffer[9:])})
                    self.receive_buffer_pointer = -1
            if frame.start_time - self.startTime > (frame.end_time-frame.start_time) * 400:
                tempMSG = AnalyzerFrame('error', self.startTime, frame.end_time, {'error': 'Timeout'})
                self.receive_buffer_pointer = -1
            self.receive_buffer_pointer += 1;
            if (self.receive_buffer_pointer == 0):
                return tempMSG

        '''
        uartbuffer = int(frame.data['data'][0])
        if (( self.receive_buffer_pointer == 0 and uartbuffer == 4) or self.receive_buffer_pointer > 0 and (not 'error' in frame.data)):
            if self.receive_buffer_pointer == 0:
                self.startTime = frame.start_time #capture the start
                self.receiveBuffer = [uartbuffer]; 
            else:
                self.receiveBuffer.append(uartbuffer);
            if(self.receive_buffer_pointer >= 2):#Byte 7 and 8 tell how big the message is
                PAR_LEN = self.receiveBuffer[2]; #Extract the parameter length from the message
                if ( self.receive_buffer_pointer >= PAR_LEN + 2): #Check to see if the entire message has been received
                    tempMSG = AnalyzerFrame('gtl', self.startTime, frame.end_time, {'message': bytes(self.receiveBuffer)})
                    self.receive_buffer_pointer = -1
            self.receive_buffer_pointer += 1;
            if (self.receive_buffer_pointer == 0):
                return tempMSG
        '''
