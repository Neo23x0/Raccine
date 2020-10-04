//**********************Category Definitions***********************
//
//  Values are 32 bit values laid out as follows:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//  +---+-+-+-----------------------+-------------------------------+
//  |Sev|C|R|     Facility          |               Code            |
//  +---+-+-+-----------------------+-------------------------------+
//
//  where
//
//      Sev - is the severity code
//
//          00 - Success
//          01 - Informational
//          10 - Warning
//          11 - Error
//
//      C - is the Customer code flag
//
//      R - is a reserved bit
//
//      Facility - is the facility code
//
//      Code - is the facility's status code
//
//
// Define the facility codes
//


//
// Define the severity codes
//


//
// MessageId: RaccineAlert
//
// MessageText:
//
// Alert
//
#define RaccineAlert                     0x00000001L

//********************End of Category Definitions*******************
// MessageIdTypeDef should NOT be altered
// Event definitions are of type DWORD
//***********************Event Definitions*************************
//
// MessageId: Alert_1337
//
// MessageText:
//
// Raccine has blocked an execution
//
#define Alert_1337                       ((DWORD)0x00000539L)

//***********************End of Event Definitions***********************