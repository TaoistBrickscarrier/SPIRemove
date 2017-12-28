#ifndef _CONDUCTOR_H_
#define _CONDUCTOR_H_

class Conductor {
private:
  Conductor();
  ~Conductor();

public:
  static Conductor* CreateInstance();
  static Conductor* GetInstance();
  bool TakeoverControl();
  void ListAllCatalog();
  void PruneID(DWORD entry_id);
  bool RefineCatalog();
  void RepairProtocols();

private:
  bool GetSocketCore();
  //bool OverrideNotify();
  //bool RenewSPIList();

  struct DCATALOGITEM;
  bool PruneID(DCATALOGITEM* item, DWORD pruning_id);

  struct DCATALOG_HEAD;
  void EnterCatalogCriticalSection(DCATALOG_HEAD* catalog);
  void LeaveCatalogCriticalSection(DCATALOG_HEAD* catalog);

private:
  static Conductor* the_instance_;

private:
  struct DCATALOGITEM {
    LIST_ENTRY catalog_list;
    volatile LONG reference_count;
    PVOID unknown0;
    ULONG unknown1;
    WSAPROTOCOL_INFOW protocol_info;
    ULONG unknown2;
    WCHAR library_path_name[MAX_PATH];
  };
  struct DCATALOG_HEAD {
    LIST_ENTRY protocol_list;
    ULONG num_catalog_entries;
    ULONG serial_access_num;
    ULONG next_catalog_entry_id;
    HKEY  reg_key;
    ULONG unknown;
  };
  struct DCATALOG_WINDOWS_7 {
    DCATALOG_HEAD header;
    CRITICAL_SECTION catalog_lock;
    /*Maybe more but I don't care*/
  };
  struct DCATALOG_WINDOWS_10 {
    DCATALOG_HEAD header;
    DWORD unknown1;
    DWORD unknown2;
    CRITICAL_SECTION catalog_lock;
    /*Maybe more but I don't care*/
  };
  struct DPROCESS {
    LONG reference_count;
    WORD version;
    BOOLEAN lock_initialized;
    DCATALOG_HEAD* protocol_catalog;
    HANDLE  protocol_catalog_change_event;
    /*Many more and I don't care.*/
  };
  struct DTHREAD {
    HANDLE reserved;
  };
  typedef DWORD(__stdcall*PrologPointer_ptr)(DPROCESS**, DTHREAD**);
  PrologPointer_ptr the_PrologPointer_;
  DPROCESS* the_d_process_;

  enum WindowsType {
    NotSupportedSystem,
    Windows_7,
    Windows_10,
  };

  WindowsType current_system_;
};

#endif // !_CONDUCTOR_H_
