/* appcontainer-named-objects.cc: Exercise AppContainer object directories.

   This file is part of Cygwin.

   This software is a copyrighted work licensed under the terms of the
   Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
   details. */

#include <windows.h>
#include <sddl.h>
#include <securityappcontainer.h>
#include <winternl.h>
#include <stdio.h>
#include <string>
#include <vector>

#define DIRECTORY_QUERY			0x0001
#define DIRECTORY_TRAVERSE		0x0002
#define DIRECTORY_CREATE_OBJECT		0x0004
#define DIRECTORY_CREATE_SUBDIRECTORY	0x0008
#define DIRECTORY_ACCESS		(READ_CONTROL \
					 | DIRECTORY_QUERY \
					 | DIRECTORY_TRAVERSE \
					 | DIRECTORY_CREATE_OBJECT \
					 | DIRECTORY_CREATE_SUBDIRECTORY)
#define OBJ_OPENIF			0x00000080L
#define ObjectNameInformation		1

typedef NTSTATUS (NTAPI *nt_create_directory_object_t)
  (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *nt_open_directory_object_t)
  (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *nt_create_event_t)
  (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, int, BOOLEAN);
typedef NTSTATUS (NTAPI *nt_open_event_t)
  (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *nt_query_object_t)
  (HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);

struct token_state
{
  HANDLE token;
  bool is_appcontainer;
  std::wstring sid;

  token_state () : token (NULL), is_appcontainer (false) {}
  ~token_state ()
  {
    if (token)
      CloseHandle (token);
  }
};

static nt_create_directory_object_t nt_create_directory_object;
static nt_open_directory_object_t nt_open_directory_object;
static nt_create_event_t nt_create_event;
static nt_open_event_t nt_open_event;
static nt_query_object_t nt_query_object;

static void
print_process_state ()
{
  typedef BOOL (WINAPI *get_process_mitigation_policy_t)
    (HANDLE, PROCESS_MITIGATION_POLICY, PVOID, SIZE_T);
  get_process_mitigation_policy_t get_process_mitigation_policy
    = (get_process_mitigation_policy_t)
      GetProcAddress (GetModuleHandleW (L"kernel32.dll"),
		      "GetProcessMitigationPolicy");
  PROCESS_MITIGATION_ASLR_POLICY policy = {};
  if (get_process_mitigation_policy
      && get_process_mitigation_policy (GetCurrentProcess (),
					ProcessASLRPolicy,
					&policy, sizeof policy))
    wprintf (L"ASLR_POLICY=bottomup:%u,force:%u,highentropy:%u,"
	     L"disallowstripped:%u\n",
	     policy.EnableBottomUpRandomization,
	     policy.EnableForceRelocateImages,
	     policy.EnableHighEntropy,
	     policy.DisallowStrippedImages);
  wprintf (L"IMAGE_BASE=%p\n", GetModuleHandleW (NULL));
}

static bool
init_ntdll ()
{
  HMODULE ntdll = GetModuleHandleW (L"ntdll.dll");
  nt_create_directory_object = (nt_create_directory_object_t)
    GetProcAddress (ntdll, "NtCreateDirectoryObject");
  nt_open_directory_object = (nt_open_directory_object_t)
    GetProcAddress (ntdll, "NtOpenDirectoryObject");
  nt_create_event = (nt_create_event_t)
    GetProcAddress (ntdll, "NtCreateEvent");
  nt_open_event = (nt_open_event_t)
    GetProcAddress (ntdll, "NtOpenEvent");
  nt_query_object = (nt_query_object_t)
    GetProcAddress (ntdll, "NtQueryObject");
  return nt_create_directory_object && nt_open_directory_object
	 && nt_create_event && nt_open_event && nt_query_object;
}

static OBJECT_ATTRIBUTES
object_attributes (UNICODE_STRING *name, HANDLE root, ULONG flags = 0,
		   PSECURITY_DESCRIPTOR sd = NULL)
{
  OBJECT_ATTRIBUTES attr;
  InitializeObjectAttributes (&attr, name, flags | OBJ_CASE_INSENSITIVE, root,
			      sd);
  return attr;
}

static UNICODE_STRING
unicode_string (const std::wstring& value)
{
  UNICODE_STRING name;
  name.Buffer = const_cast<PWCHAR> (value.c_str ());
  name.Length = (USHORT) (value.size () * sizeof (WCHAR));
  name.MaximumLength = name.Length + sizeof (WCHAR);
  return name;
}

static NTSTATUS
create_directory (HANDLE root, const std::wstring& name, HANDLE *result,
		  PSECURITY_DESCRIPTOR sd = NULL)
{
  UNICODE_STRING uname = unicode_string (name);
  OBJECT_ATTRIBUTES attr = object_attributes (&uname, root, OBJ_OPENIF, sd);
  return nt_create_directory_object (result, DIRECTORY_ACCESS, &attr);
}

static NTSTATUS
open_directory (HANDLE root, const std::wstring& name, HANDLE *result)
{
  UNICODE_STRING uname = unicode_string (name);
  OBJECT_ATTRIBUTES attr = object_attributes (&uname, root);
  return nt_open_directory_object (result, DIRECTORY_ACCESS, &attr);
}

static NTSTATUS
create_event (HANDLE root, const std::wstring& name, HANDLE *result,
	      PSECURITY_DESCRIPTOR sd = NULL)
{
  UNICODE_STRING uname = unicode_string (name);
  OBJECT_ATTRIBUTES attr = object_attributes (&uname, root, OBJ_OPENIF, sd);
  return nt_create_event (result, EVENT_ALL_ACCESS, &attr, 0, FALSE);
}

static NTSTATUS
open_event (HANDLE root, const std::wstring& name, HANDLE *result)
{
  UNICODE_STRING uname = unicode_string (name);
  OBJECT_ATTRIBUTES attr = object_attributes (&uname, root);
  return nt_open_event (result, EVENT_ALL_ACCESS, &attr);
}

static std::wstring
query_name (HANDLE handle)
{
  ULONG required = 0;
  nt_query_object (handle, (OBJECT_INFORMATION_CLASS) ObjectNameInformation,
		   NULL, 0, &required);
  if (!required)
    return L"<unknown>";

  std::vector<BYTE> buffer (required);
  NTSTATUS status
    = nt_query_object (handle,
		       (OBJECT_INFORMATION_CLASS) ObjectNameInformation,
		       buffer.data (), required, &required);
  if (status < 0)
    return L"<query-failed>";

  UNICODE_STRING *name = (UNICODE_STRING *) buffer.data ();
  return std::wstring (name->Buffer, name->Length / sizeof (WCHAR));
}

static bool
read_token (token_state& state)
{
  if (!OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY, &state.token))
    return false;

  DWORD value = 0;
  DWORD size = 0;
  if (!GetTokenInformation (state.token, TokenIsAppContainer, &value,
			    sizeof value, &size))
    return false;
  state.is_appcontainer = value != 0;
  if (!state.is_appcontainer)
    return true;

  GetTokenInformation (state.token, TokenAppContainerSid, NULL, 0, &size);
  if (!size)
    return false;
  std::vector<BYTE> buffer (size);
  if (!GetTokenInformation (state.token, TokenAppContainerSid, buffer.data (),
			    size, &size))
    return false;
  TOKEN_APPCONTAINER_INFORMATION *info
    = (TOKEN_APPCONTAINER_INFORMATION *) buffer.data ();
  PWSTR sid = NULL;
  if (!ConvertSidToStringSidW (info->TokenAppContainer, &sid))
    return false;
  state.sid = sid;
  LocalFree (sid);
  return true;
}

static PSECURITY_DESCRIPTOR
token_security_descriptor (HANDLE token, ACCESS_MASK access,
			   std::vector<BYTE>& storage)
{
  DWORD user_size = 0;
  DWORD app_size = 0;
  GetTokenInformation (token, TokenUser, NULL, 0, &user_size);
  GetTokenInformation (token, TokenAppContainerSid, NULL, 0, &app_size);
  if (!user_size || !app_size)
    return NULL;

  std::vector<BYTE> user_buffer (user_size);
  std::vector<BYTE> app_buffer (app_size);
  if (!GetTokenInformation (token, TokenUser, user_buffer.data (), user_size,
			    &user_size)
      || !GetTokenInformation (token, TokenAppContainerSid,
			       app_buffer.data (), app_size, &app_size))
    return NULL;

  TOKEN_USER *user = (TOKEN_USER *) user_buffer.data ();
  TOKEN_APPCONTAINER_INFORMATION *app
    = (TOKEN_APPCONTAINER_INFORMATION *) app_buffer.data ();
  DWORD acl_size = sizeof (ACL)
		   + 2 * (sizeof (ACCESS_ALLOWED_ACE) - sizeof (DWORD))
		   + GetLengthSid (user->User.Sid)
		   + GetLengthSid (app->TokenAppContainer);
  storage.resize (sizeof (SECURITY_DESCRIPTOR) + acl_size);
  PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR) storage.data ();
  PACL acl = (PACL) (storage.data () + sizeof (SECURITY_DESCRIPTOR));
  if (!InitializeSecurityDescriptor (sd, SECURITY_DESCRIPTOR_REVISION)
      || !InitializeAcl (acl, acl_size, ACL_REVISION)
      || !AddAccessAllowedAce (acl, ACL_REVISION, access, user->User.Sid)
      || !AddAccessAllowedAce (acl, ACL_REVISION, access,
			       app->TokenAppContainer)
      || !SetSecurityDescriptorDacl (sd, TRUE, acl, FALSE))
    return NULL;
  return sd;
}

static bool
private_path (HANDLE token, std::wstring& raw, std::wstring& canonical)
{
  HMODULE kernelbase = GetModuleHandleW (L"KernelBase.dll");
  typedef BOOL (WINAPI *get_path_t) (HANDLE, PSID, ULONG, LPWSTR, PULONG);
  get_path_t get_path = (get_path_t)
    GetProcAddress (kernelbase, "GetAppContainerNamedObjectPath");
  if (!get_path)
    return false;

  ULONG required = 0;
  get_path (token, NULL, 0, NULL, &required);
  if (!required)
    return false;
  std::vector<WCHAR> buffer (required);
  ULONG returned = 0;
  if (!get_path (token, NULL, required, buffer.data (), &returned))
    return false;
  raw = buffer.data ();
  if (!raw.empty () && raw[0] == L'\\')
    canonical = raw;
  else
    {
      DWORD session;
      if (!ProcessIdToSessionId (GetCurrentProcessId (), &session))
	return false;
      WCHAR prefix[64];
      swprintf (prefix, 64, L"\\Sessions\\%lu\\", session);
      canonical = prefix;
      canonical += raw;
    }
  return true;
}

static bool
write_ready_file (const std::wstring& path, const std::wstring& value)
{
  HANDLE file = CreateFileW (path.c_str (), GENERIC_WRITE, FILE_SHARE_READ,
			     NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (file == INVALID_HANDLE_VALUE)
    return false;
  int length = WideCharToMultiByte (CP_UTF8, 0, value.c_str (), -1, NULL, 0,
				   NULL, NULL);
  std::vector<char> buffer (length);
  WideCharToMultiByte (CP_UTF8, 0, value.c_str (), -1, buffer.data (), length,
		       NULL, NULL);
  DWORD written;
  bool ok = WriteFile (file, buffer.data (), length - 1, &written, NULL)
	    && written == (DWORD) length - 1;
  CloseHandle (file);
  return ok;
}

static int
run_child (const std::wstring& root_path)
{
  print_process_state ();
  HANDLE root = NULL;
  NTSTATUS root_status = open_directory (NULL, root_path, &root);
  wprintf (L"CHILD_ROOT_STATUS=0x%08lx\n", (ULONG) root_status);
  if (root_status < 0)
    return 20;

  HANDLE shared = NULL;
  NTSTATUS shared_status = open_directory (root, L"Shared", &shared);
  wprintf (L"CHILD_SHARED_STATUS=0x%08lx\n", (ULONG) shared_status);
  if (shared_status < 0)
    {
      CloseHandle (root);
      return 21;
    }

  HANDLE event = NULL;
  NTSTATUS event_status = open_event (shared, L"event", &event);
  wprintf (L"CHILD_EVENT_STATUS=0x%08lx\n", (ULONG) event_status);
  if (event)
    CloseHandle (event);
  CloseHandle (shared);
  CloseHandle (root);
  return event_status < 0 ? 22 : 0;
}

static int
run_open (const std::wstring& root_path)
{
  token_state token;
  if (!read_token (token))
    {
      fwprintf (stderr, L"ERROR=token:%lu\n", GetLastError ());
      return 10;
    }
  wprintf (L"IS_APPCONTAINER=%d\n", token.is_appcontainer);
  print_process_state ();
  if (!token.sid.empty ())
    wprintf (L"APPCONTAINER_SID=%ls\n", token.sid.c_str ());

  HANDLE root = NULL;
  NTSTATUS status = open_directory (NULL, root_path, &root);
  wprintf (L"FOREIGN_OPEN_STATUS=0x%08lx\n", (ULONG) status);
  if (root)
    CloseHandle (root);
  return status < 0 ? 2 : 0;
}

static int
run_parent (const std::wstring& ready_file, DWORD hold_seconds)
{
  token_state token;
  if (!read_token (token))
    {
      fwprintf (stderr, L"ERROR=token:%lu\n", GetLastError ());
      return 10;
    }
  wprintf (L"IS_APPCONTAINER=%d\n", token.is_appcontainer);
  print_process_state ();
  if (!token.is_appcontainer)
    {
      wprintf (L"SKIP=not-appcontainer\n");
      return 0;
    }
  wprintf (L"APPCONTAINER_SID=%ls\n", token.sid.c_str ());

  std::wstring raw;
  std::wstring canonical;
  if (!private_path (token.token, raw, canonical))
    {
      fwprintf (stderr, L"ERROR=private-path:%lu\n", GetLastError ());
      return 11;
    }
  wprintf (L"PRIVATE_PATH_RAW=%ls\n", raw.c_str ());
  wprintf (L"PRIVATE_PATH_CANONICAL=%ls\n", canonical.c_str ());

  HANDLE private_root = NULL;
  NTSTATUS status = open_directory (NULL, canonical, &private_root);
  wprintf (L"PRIVATE_ROOT_STATUS=0x%08lx\n", (ULONG) status);
  if (status < 0)
    return 12;

  WCHAR run_name[80];
  swprintf (run_name, 80, L"MsysProbe-%lu-%llu", GetCurrentProcessId (),
	    GetTickCount64 ());
  std::wstring run_path = canonical + L"\\" + run_name;

  HANDLE run_root = NULL;
  HANDLE shared = NULL;
  HANDLE session = NULL;
  HANDLE shared_event = NULL;
  HANDLE session_event = NULL;
  int result = 0;
  std::vector<BYTE> directory_sd_storage;
  std::vector<BYTE> event_sd_storage;
  PSECURITY_DESCRIPTOR directory_sd
    = token_security_descriptor (token.token, DIRECTORY_ACCESS,
				 directory_sd_storage);
  PSECURITY_DESCRIPTOR event_sd
    = token_security_descriptor (token.token, EVENT_ALL_ACCESS,
				 event_sd_storage);
  if (!directory_sd || !event_sd)
    {
      CloseHandle (private_root);
      return 24;
    }

  status = create_directory (private_root, run_name, &run_root, directory_sd);
  wprintf (L"RUN_ROOT_STATUS=0x%08lx\n", (ULONG) status);
  if (status < 0)
    result = 13;
  if (!result)
    {
      status = create_directory (run_root, L"Shared", &shared, directory_sd);
      wprintf (L"SHARED_STATUS=0x%08lx\n", (ULONG) status);
      if (status < 0)
	result = 14;
    }
  if (!result)
    {
      status = create_directory (run_root, L"Session", &session, directory_sd);
      wprintf (L"SESSION_STATUS=0x%08lx\n", (ULONG) status);
      if (status < 0)
	result = 15;
    }
  if (!result)
    {
      status = create_event (shared, L"event", &shared_event, event_sd);
      wprintf (L"SHARED_EVENT_STATUS=0x%08lx\n", (ULONG) status);
      if (status < 0)
	result = 16;
    }
  if (!result)
    {
      status = create_event (session, L"event", &session_event, event_sd);
      wprintf (L"SESSION_EVENT_STATUS=0x%08lx\n", (ULONG) status);
      if (status < 0)
	result = 17;
    }

  if (!result)
    {
      wprintf (L"RUN_ROOT_PATH=%ls\n", run_path.c_str ());
      wprintf (L"RUN_ROOT_NATIVE=%ls\n", query_name (run_root).c_str ());
      wprintf (L"SHARED_NATIVE=%ls\n", query_name (shared).c_str ());
      wprintf (L"SESSION_NATIVE=%ls\n", query_name (session).c_str ());

      WCHAR module[MAX_PATH];
      GetModuleFileNameW (NULL, module, MAX_PATH);
      std::wstring command = L"\"";
      command += module;
      command += L"\" --child \"";
      command += run_path;
      command += L"\"";
      std::vector<WCHAR> command_buffer (command.begin (), command.end ());
      command_buffer.push_back (L'\0');
      STARTUPINFOW si = { sizeof si };
      PROCESS_INFORMATION pi = {};
      if (!CreateProcessW (module, command_buffer.data (), NULL, NULL, TRUE, 0,
			   NULL, NULL, &si, &pi))
	result = 18;
      else
	{
	  WaitForSingleObject (pi.hProcess, 30000);
	  DWORD exit_code;
	  GetExitCodeProcess (pi.hProcess, &exit_code);
	  wprintf (L"CHILD_EXIT=%lu\n", exit_code);
	  if (exit_code)
	    result = 19;
	  CloseHandle (pi.hThread);
	  CloseHandle (pi.hProcess);
	}
    }

  if (!result && !ready_file.empty ()
      && !write_ready_file (ready_file, run_path))
    result = 23;
  fflush (stdout);
  if (!result && hold_seconds)
    Sleep (hold_seconds * 1000);

  if (session_event)
    CloseHandle (session_event);
  if (shared_event)
    CloseHandle (shared_event);
  if (session)
    CloseHandle (session);
  if (shared)
    CloseHandle (shared);
  if (run_root)
    CloseHandle (run_root);
  CloseHandle (private_root);
  return result;
}

int wmain (int argc, wchar_t **argv)
{
  if (!init_ntdll ())
    {
      fwprintf (stderr, L"ERROR=ntdll-entry-points\n");
      return 1;
    }
  if (argc == 3 && !wcscmp (argv[1], L"--child"))
    return run_child (argv[2]);
  if (argc == 3 && !wcscmp (argv[1], L"--open"))
    return run_open (argv[2]);

  std::wstring ready_file;
  DWORD hold_seconds = 0;
  for (int i = 1; i < argc; ++i)
    if (!wcscmp (argv[i], L"--ready-file") && i + 1 < argc)
      ready_file = argv[++i];
    else if (!wcscmp (argv[i], L"--hold-seconds") && i + 1 < argc)
      hold_seconds = wcstoul (argv[++i], NULL, 10);
    else
      {
	fwprintf (stderr, L"usage: %ls [--ready-file path] "
		 L"[--hold-seconds seconds]\n", argv[0]);
	return 2;
      }
  return run_parent (ready_file, hold_seconds);
}
