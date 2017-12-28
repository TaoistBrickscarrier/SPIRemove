#include "stdafx.h"
#include "conductor.h"

#pragma warning(disable: 4996)

Conductor* Conductor::the_instance_ = NULL;

Conductor::Conductor() {
  the_PrologPointer_ = NULL;
  the_d_process_ = NULL;

  OSVERSIONINFO os_version = { sizeof(os_version) };
  ::GetVersionEx(&os_version);
  current_system_ = NotSupportedSystem;
  if (os_version.dwMajorVersion == 6) {
    if (os_version.dwMinorVersion == 1) {
      current_system_ = Windows_7;
    } else if (os_version.dwMinorVersion == 2) {
      current_system_ = Windows_10;
    }
  }
}

Conductor::~Conductor() {
}

Conductor* Conductor::CreateInstance() {
  if (the_instance_ == NULL) {
    the_instance_ = new Conductor();
  }
  return the_instance_;
}

Conductor* Conductor::GetInstance() {
  return the_instance_;
}

bool Conductor::TakeoverControl() {
  if (current_system_ == NotSupportedSystem) {
    return false;
  }
  WSADATA wsa_data = { 0 };
  if (::WSAStartup(MAKEWORD(2, 2), &wsa_data) != ERROR_SUCCESS) {
    printf("Fail to Startup WinSock!\r\n");
    return false;
  }
  if (!GetSocketCore()) {
    return false;
  }
  return true;
}

bool Conductor::GetSocketCore() {
  HMODULE ws2_32 = NULL;
  ULONG ws2_32_size = 0;
  UCHAR* ptr_WSASocketW = NULL;
  
  bool found = false;

  ws2_32 = ::GetModuleHandle(_T("ws2_32.dll"));
  if (ws2_32 == NULL) {
    printf("There is no ws2_32.dll in process.\r\n");
    return false;
  } else {
    /*
    I really do not care if it's valid PE.
    We should trust M$.
    */
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)ws2_32;
    PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(
      (PUCHAR)ws2_32 + dos_header->e_lfanew);
    ws2_32_size = nt_header->OptionalHeader.SizeOfImage;
    if (ws2_32_size == 0) {
      printf("Zero size ws2_32.dll in process.\r\n");
      return false;
    }
  }

  ptr_WSASocketW = (UCHAR*)::GetProcAddress(ws2_32, "WSASocketW");
  if (ptr_WSASocketW == NULL) {
    printf("May an ancient version, not supported.\r\n");
    return false;
  }

  // Search for local socket's PrologPointer
  if (current_system_ == Windows_7) {
    for (int i = 0; i < 100; ++i) {
      if (ptr_WSASocketW[0] == 0x50 &&
          ptr_WSASocketW[1] == 0xff &&
          ptr_WSASocketW[2] == 0x15) {
        ptr_WSASocketW += 3;
        PrologPointer_ptr _PrologPointer = **(PrologPointer_ptr**)ptr_WSASocketW;
        if ((ULONG_PTR)_PrologPointer > (ULONG_PTR)ws2_32 &&
          (ULONG_PTR)_PrologPointer < (ULONG_PTR)ws2_32 + ws2_32_size) {
          the_PrologPointer_ = _PrologPointer;
          found = true;
          break;
        }
      }
      ++ptr_WSASocketW;
    }
  } else if (current_system_ == Windows_10) {
    for (int i = 0; i < 100; ++i) {
      if (ptr_WSASocketW[0] == 0x8b &&
          ptr_WSASocketW[1] == 0x35) {
        ptr_WSASocketW += 2;
        PrologPointer_ptr _PrologPointer = **(PrologPointer_ptr**)ptr_WSASocketW;
        if ((ULONG_PTR)_PrologPointer > (ULONG_PTR)ws2_32 &&
          (ULONG_PTR)_PrologPointer < (ULONG_PTR)ws2_32 + ws2_32_size) {
          the_PrologPointer_ = _PrologPointer;
          found = true;
          break;
        }
      }
      ++ptr_WSASocketW;
    }
  }

  if (!found) {
    printf("No PrologPointer found\r\n");
    return false;
  } else {
    DPROCESS* process = NULL;
    DTHREAD * thread = NULL;
    DWORD err_code = the_PrologPointer_(&process, &thread);
    if (err_code != ERROR_SUCCESS) {
      printf("Calling PrologPointer failed!\r\n");
      return false;
    }
    the_d_process_ = process;
  }

  return true;
}

bool Conductor::RefineCatalog() {
  if (the_d_process_ == NULL) {
    return false;
  }

  DCATALOGITEM* catalog_item = NULL;
  LIST_ENTRY* list_node = NULL;
  LIST_ENTRY* list_head = NULL;
  DCATALOG_HEAD* protocol_catalog = the_d_process_->protocol_catalog;
  bool cleared = false;

  EnterCatalogCriticalSection(protocol_catalog);
  while (!cleared) {
    list_head = &protocol_catalog->protocol_list;
    for (list_node = list_head->Flink;
         list_node != list_head;
         list_node = list_node->Flink) {
      catalog_item = CONTAINING_RECORD(list_node, DCATALOGITEM, catalog_list);
      if (catalog_item->protocol_info.ProtocolChain.ChainLen > 1) {
        continue;
      }
      if (::StrStrI(catalog_item->library_path_name, _T("xfilter.dll")) ||
          ::StrStrI(catalog_item->library_path_name, _T("sangfor"))) {
        printf("Pruning : %d\r\n", catalog_item->protocol_info.dwCatalogEntryId);
        PruneID(catalog_item->protocol_info.dwCatalogEntryId);
        break;
      }
    }
    cleared = (list_node == list_head);
  }
  LeaveCatalogCriticalSection(protocol_catalog);
  return true;
}

void Conductor::RepairProtocols() {
  /*
  In windows 7, 1001~1010 items should be "%SystemRoot%\system32\mswsock.dll"
  Not implied in Windows 10.
  */
  if (the_d_process_ == NULL) {
    return;
  }

  if (current_system_ != Windows_7) {
    return;
  }

  DCATALOGITEM* catalog_item = NULL;
  LIST_ENTRY* list_node = NULL;
  LIST_ENTRY* list_head = NULL;
  DCATALOG_HEAD* protocol_catalog = the_d_process_->protocol_catalog;

  EnterCatalogCriticalSection(protocol_catalog);
  list_head = &protocol_catalog->protocol_list;
  for (list_node = list_head->Flink;
       list_node != list_head;
       list_node = list_node->Flink) {
    catalog_item = CONTAINING_RECORD(list_node, DCATALOGITEM, catalog_list);
    DWORD entry_id = catalog_item->protocol_info.dwCatalogEntryId;
    if (entry_id > 1000 && entry_id < 1011) {
      wcscpy_s(catalog_item->library_path_name,
               L"%SystemRoot%\\system32\\mswsock.dll");
    }
  }
  LeaveCatalogCriticalSection(protocol_catalog);
}

//bool Conductor::OverrideNotify() {
//  return true;
//}
//
//bool Conductor::RenewSPIList() {
//  return true;
//}

void Conductor::ListAllCatalog() {
  if (the_d_process_ == NULL) {
    return;
  }

  DCATALOGITEM* catalog_item = NULL;
  LIST_ENTRY* list_node = NULL;
  LIST_ENTRY* list_head = NULL;
  DCATALOG_HEAD* protocol_catalog = the_d_process_->protocol_catalog;

  printf("Total entries: %d\r\nSerial access number : %d\r\nNext entry: %d\r\n\r\n",
         protocol_catalog->num_catalog_entries,
         protocol_catalog->serial_access_num,
         protocol_catalog->next_catalog_entry_id);

  EnterCatalogCriticalSection(protocol_catalog);
  list_head = &protocol_catalog->protocol_list;
  for (list_node = list_head->Flink;
       list_node != list_head;
       list_node = list_node->Flink) {
    catalog_item = CONTAINING_RECORD(list_node, DCATALOGITEM, catalog_list);
    wprintf(L"Protocol: %s\r\nDll name: %s\r\nID:%d\r\nReference:%d\r\n",
            catalog_item->protocol_info.szProtocol,
            catalog_item->library_path_name,
            catalog_item->protocol_info.dwCatalogEntryId,
            catalog_item->reference_count);
    printf("Guid : {%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}\r\n",
           catalog_item->protocol_info.ProviderId.Data1,
           catalog_item->protocol_info.ProviderId.Data2,
           catalog_item->protocol_info.ProviderId.Data3,
           catalog_item->protocol_info.ProviderId.Data4[0],
           catalog_item->protocol_info.ProviderId.Data4[1],
           catalog_item->protocol_info.ProviderId.Data4[2],
           catalog_item->protocol_info.ProviderId.Data4[3],
           catalog_item->protocol_info.ProviderId.Data4[4],
           catalog_item->protocol_info.ProviderId.Data4[5],
           catalog_item->protocol_info.ProviderId.Data4[6],
           catalog_item->protocol_info.ProviderId.Data4[7]);
    printf("Services flag 1 : %08x\r\n",
           catalog_item->protocol_info.dwServiceFlags1);
    printf("Family : %d Socket type : %d Protocol: %d\r\n",
           catalog_item->protocol_info.iAddressFamily,
           catalog_item->protocol_info.iSocketType,
           catalog_item->protocol_info.iProtocol);
    printf("There is %d node in the chain:\t",
           catalog_item->protocol_info.ProtocolChain.ChainLen);
    for (int i = 0, size = catalog_item->protocol_info.ProtocolChain.ChainLen;
         i < size;
         ++i) {
      printf("%d\t", catalog_item->protocol_info.ProtocolChain.ChainEntries[i]);
    }
    printf("\r\n\r\n");
  }
  LeaveCatalogCriticalSection(protocol_catalog);
}

void Conductor::PruneID(DWORD entry_id) {
  DCATALOGITEM* catalog_item = NULL;
  LIST_ENTRY* list_node = NULL;
  LIST_ENTRY* list_head = NULL;
  DCATALOG_HEAD* protocol_catalog = the_d_process_->protocol_catalog;

  EnterCatalogCriticalSection(protocol_catalog);
  list_head = &protocol_catalog->protocol_list;
  for (list_node = list_head->Flink;
       list_node != list_head;
       ) {
    catalog_item = CONTAINING_RECORD(list_node, DCATALOGITEM, catalog_list);
    list_node = list_node->Flink;
    if (PruneID(catalog_item, entry_id)) {
      --protocol_catalog->num_catalog_entries;
    }
  }
  LeaveCatalogCriticalSection(protocol_catalog);
}

bool Conductor::PruneID(DCATALOGITEM* item, DWORD pruning_id) {
  int item_chain_len = item->protocol_info.ProtocolChain.ChainLen;

  if (item_chain_len > MAX_PROTOCOL_CHAIN) {
    // Abnormal node.
    LIST_ENTRY* list_node = &item->catalog_list;
    list_node->Flink->Blink = list_node->Blink;
    list_node->Blink->Flink = list_node->Flink;
    PruneID(item->protocol_info.dwCatalogEntryId);
    InterlockedDecrement(&item->reference_count);
    return true;
  }

  // Clear protocol chain.
  if (item_chain_len > 1) {
    DWORD* chain_entries = item->protocol_info.ProtocolChain.ChainEntries;
    DWORD* current_entry = chain_entries;
    for (int i = 0; i < item_chain_len; ++i) {
      if (*chain_entries == pruning_id) {
        if (i == 0 ||
            i == item_chain_len - 1 ||
            item->protocol_info.ProtocolChain.ChainLen == 2) {
          LIST_ENTRY* list_node = &item->catalog_list;
          list_node->Flink->Blink = list_node->Blink;
          list_node->Blink->Flink = list_node->Flink;
          PruneID(item->protocol_info.dwCatalogEntryId);
          InterlockedDecrement(&item->reference_count);
          return true;
        }
        memcpy(current_entry, current_entry + 1,
               sizeof(DWORD)*(item_chain_len - i - 1));
        --item->protocol_info.ProtocolChain.ChainLen;
      } else {
        ++current_entry;
        chain_entries = current_entry;
      }
    }
    return false;
  }

  if (// item_chain_len == 0 &&
      item->protocol_info.dwCatalogEntryId == pruning_id) {
    LIST_ENTRY* list_node = &item->catalog_list;
    list_node->Flink->Blink = list_node->Blink;
    list_node->Blink->Flink = list_node->Flink;
    InterlockedDecrement(&item->reference_count);
    return true;
  }

  return false;
}

void Conductor::EnterCatalogCriticalSection(DCATALOG_HEAD* catalog) {
  switch (current_system_) {
    case Windows_7: {
      ::EnterCriticalSection(&((DCATALOG_WINDOWS_7*)catalog)->catalog_lock);
      break;
    }
    case Windows_10: {
      ::EnterCriticalSection(&((DCATALOG_WINDOWS_10*)catalog)->catalog_lock);
      break;
    }
    case NotSupportedSystem:
    default:
      break;
  }
}

void Conductor::LeaveCatalogCriticalSection(DCATALOG_HEAD* catalog) {
  switch (current_system_) {
    case Windows_7: {
      ::EnterCriticalSection(&((DCATALOG_WINDOWS_7*)catalog)->catalog_lock);
      break;
    }
    case Windows_10: {
      ::EnterCriticalSection(&((DCATALOG_WINDOWS_10*)catalog)->catalog_lock);
      break;
    }
    case NotSupportedSystem:
    default:
      break;
  }
}

