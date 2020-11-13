#include "EventLogHelper.h"

#pragma comment(lib,"wevtapi.lib")

namespace eventloghelper
{
//sysmon log is admin only by default.  Add a Read ACE for interactive with (A;; 0x1;;; IU);
//> wevtutil  sl "Microsoft-Windows-Sysmon/Operational" / ca:D:(A;; 0xf0007;;; SY)(A;; 0x7;;; BA)(A;; 0x1;;; BO)(A;; 0x1;;; SO)(A;; 0x1;;; S - 1 - 5 - 32 - 573)(A;; 0x1;;; IU)
//
//> wevtutil  gl "Microsoft-Windows-Sysmon/Operational"
//name: Microsoft - Windows - Sysmon / Operational
//channelAccess : D:(A;; 0xf0007;;; SY)(A;; 0x7;;; BA)(A;; 0x1;;; BO)(A;; 0x1;;; SO)(A;; 0x1;;; S - 1 - 5 - 32 - 573)(A;; 0x1;;; IU)

    std::wstring GetEvents()
    {
        PWSTR Buffer;
        ULONG BufferSize;
        ULONG BufferSizeNeeded;
        ULONG Count;
        EVT_HANDLE Event;
        ULONG Status;

        UINT cEventCountMax = 10;
        UINT cEvent = 0;

        DWORD dwSessionId = utils::getCurrentSessionId();
        std::wstring session_id = L"<Data Name='TerminalSessionId'>" + std::to_wstring(dwSessionId) + L"</Data>";
        std::wstring current_usersid = L"<Security UserID='" + utils::getUserSid() + L"'/>";
        std::wstring ignore_process = L"<Data Name='Image'>C:\\Program Files\\Raccine\\";
        std::wstring ignore_process2 = L"<Data Name='Image'>C:\\Windows\\System32\\conhost.exe";

        std::wstring query = L"*[System[Task=1]]";
        EVT_HANDLE Query = EvtQuery(
            NULL,
            L"Microsoft-Windows-Sysmon/Operational", 
            query.c_str(),
            EvtQueryReverseDirection 
        );

        std::wstring event_detail(L"");

        //
        // Read each event and render it as XML.
        //

        Buffer = NULL;
        BufferSize = 0;
        BufferSizeNeeded = 0;

        while ((EvtNext(Query, 1, &Event, INFINITE, 0, &Count) != FALSE) && (cEvent < cEventCountMax))
        {
            do {
                if (BufferSizeNeeded > BufferSize) {
                    LocalFree(Buffer);
                    BufferSize = BufferSizeNeeded;
                    Buffer = (PWSTR) LocalAlloc(LPTR, BufferSize);
                    if (Buffer == NULL) {
                        Status = ERROR_OUTOFMEMORY;
                        BufferSize = 0;
                        break;
                    }
                }

                if (EvtRender(NULL,
                    Event,
                    EvtRenderEventXml,
                    BufferSize,
                    Buffer,
                    &BufferSizeNeeded,
                    &Count) != FALSE) 
                {
                    Status = ERROR_SUCCESS;
                }
                else {
                    Status = GetLastError();
                }
            } while (Status == ERROR_INSUFFICIENT_BUFFER);

            //
            // Display either the event xml or an error message.
            //

            if (Status == ERROR_SUCCESS) 
            {
                std::wstring xml_event(Buffer);

                //only process events for the current session
                if (xml_event.find(session_id) > 0 && 
                    xml_event.find(current_usersid) > 0 && 
                    xml_event.find(ignore_process) == std::wstring::npos &&
                    xml_event.find(ignore_process2) == std::wstring::npos)
                {
                    event_detail += xml_event + L"\r\n";
                    cEvent++;
                }
                else
                {
                    ; // skip this event
                }
            }


            EvtClose(Event);
        }

        //
        // When EvtNextChannelPath returns ERROR_NO_MORE_ITEMS, we have actually
        // iterated through all matching events and thus succeeded.
        //

        Status = GetLastError();
        if (Status == ERROR_NO_MORE_ITEMS) {
            Status = ERROR_SUCCESS;
        }

        //
        // Free resources.
        //

        EvtClose(Query);
        LocalFree(Buffer);
        return event_detail;
    }

}