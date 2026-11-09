/* appcontainer-launcher.cc: Run a Cygwin testsuite child in an AppContainer.

   This file is part of Cygwin.

   This software is a copyrighted work licensed under the terms of the
   Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
   details. */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif

#include <windows.h>
#include <aclapi.h>
#include <securityappcontainer.h>
#include <userenv.h>

#include <stdio.h>
#include <string>
#include <vector>
#include <wchar.h>

struct acl_backup
{
  std::wstring path;
  PSECURITY_DESCRIPTOR descriptor;
  PACL dacl;
};

class temporary_acl
{
  std::vector<acl_backup> backups;

public:
  DWORD
  grant (const std::wstring& path, PSID sid, DWORD access)
  {
    PSECURITY_DESCRIPTOR descriptor = NULL;
    PACL old_dacl = NULL;
    DWORD error = GetNamedSecurityInfoW ((LPWSTR) path.c_str (), SE_FILE_OBJECT,
					 DACL_SECURITY_INFORMATION, NULL, NULL,
					 &old_dacl, NULL, &descriptor);
    if (error != ERROR_SUCCESS)
      return error;

    EXPLICIT_ACCESSW entry = {};
    entry.grfAccessPermissions = access;
    entry.grfAccessMode = GRANT_ACCESS;
    entry.grfInheritance = NO_INHERITANCE;
    entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    entry.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    entry.Trustee.ptstrName = (LPWSTR) sid;

    PACL new_dacl = NULL;
    error = SetEntriesInAclW (1, &entry, old_dacl, &new_dacl);
    if (error != ERROR_SUCCESS)
      {
	LocalFree (descriptor);
	return error;
      }

    backups.push_back ({ path, descriptor, old_dacl });
    error = SetNamedSecurityInfoW ((LPWSTR) path.c_str (), SE_FILE_OBJECT,
				   DACL_SECURITY_INFORMATION, NULL, NULL,
				   new_dacl, NULL);
    if (new_dacl)
      LocalFree (new_dacl);
    if (error != ERROR_SUCCESS)
      {
	backups.pop_back ();
	LocalFree (descriptor);
	return error;
      }
    return ERROR_SUCCESS;
  }

  DWORD
  restore ()
  {
    DWORD first_error = ERROR_SUCCESS;
    for (size_t i = backups.size (); i > 0; --i)
      {
	acl_backup& backup = backups[i - 1];
	if (!backup.descriptor)
	  continue;
	DWORD error
	  = SetNamedSecurityInfoW ((LPWSTR) backup.path.c_str (), SE_FILE_OBJECT,
				   DACL_SECURITY_INFORMATION, NULL, NULL,
				   backup.dacl, NULL);
	if (first_error == ERROR_SUCCESS && error != ERROR_SUCCESS)
	  first_error = error;
	if (error == ERROR_SUCCESS)
	  {
	    LocalFree (backup.descriptor);
	    backup.descriptor = NULL;
	  }
      }
    if (first_error == ERROR_SUCCESS)
      backups.clear ();
    return first_error;
  }

  ~temporary_acl ()
  {
    restore ();
  }
};

static std::wstring
full_path (const std::wstring& path)
{
  DWORD needed = GetFullPathNameW (path.c_str (), 0, NULL, NULL);
  if (!needed)
    return std::wstring ();
  std::vector<WCHAR> buffer (needed + 1);
  DWORD length
    = GetFullPathNameW (path.c_str (), buffer.size (), buffer.data (), NULL);
  if (!length || length >= buffer.size ())
    return std::wstring ();
  return std::wstring (buffer.data (), length);
}

static std::wstring
parent_path (const std::wstring& path)
{
  size_t slash = path.find_last_of (L"\\/");
  if (slash == std::wstring::npos)
    return std::wstring ();
  if (slash == 2 && path.size () >= 3 && path[1] == L':')
    return path.substr (0, 3);
  return path.substr (0, slash);
}

static bool
grant_ancestor_traverse (const std::wstring& root, PSID sid,
			 temporary_acl& acl, DWORD& error)
{
  std::vector<std::wstring> ancestors;
  std::wstring path = parent_path (root);
  while (path.size () > 3)
    {
      ancestors.push_back (path);
      path = parent_path (path);
    }
  for (auto it = ancestors.rbegin (); it != ancestors.rend (); ++it)
    {
      error = acl.grant (*it, sid, FILE_TRAVERSE | FILE_READ_ATTRIBUTES);
      if (error != ERROR_SUCCESS)
	return false;
    }
  return true;
}

static bool
grant_test_files (const std::wstring& root, const std::wstring& child,
		  const std::wstring& dll, PSID sid, temporary_acl& acl,
		  DWORD& error)
{
  error = acl.grant (root, sid, FILE_TRAVERSE | FILE_READ_ATTRIBUTES);
  if (error != ERROR_SUCCESS)
    return false;
  error = acl.grant (parent_path (child), sid,
		     FILE_TRAVERSE | FILE_READ_ATTRIBUTES);
  if (error != ERROR_SUCCESS)
    return false;
  error = acl.grant (child, sid, FILE_GENERIC_READ | FILE_EXECUTE);
  if (error != ERROR_SUCCESS)
    return false;
  error = acl.grant (dll, sid, FILE_GENERIC_READ | FILE_EXECUTE);
  return error == ERROR_SUCCESS;
}

static std::wstring
quote_argument (const std::wstring& arg)
{
  std::wstring quoted = L"\"";
  size_t slashes = 0;
  for (WCHAR c : arg)
    {
      if (c == L'\\')
	{
	  ++slashes;
	  continue;
	}
      if (c == L'"')
	quoted.append (slashes * 2 + 1, L'\\');
      else
	quoted.append (slashes, L'\\');
      quoted.push_back (c);
      slashes = 0;
    }
  quoted.append (slashes * 2, L'\\');
  quoted.push_back (L'"');
  return quoted;
}

static bool
is_appcontainer (HANDLE process)
{
  HANDLE token = NULL;
  DWORD value = 0;
  DWORD size = 0;
  if (!OpenProcessToken (process, TOKEN_QUERY, &token))
    return false;
  BOOL ok = GetTokenInformation (token, TokenIsAppContainer, &value,
				 sizeof value, &size);
  CloseHandle (token);
  return ok && value != 0;
}

static bool
skip_error (DWORD error)
{
  return error == ERROR_ACCESS_DENIED || error == ERROR_NOT_SUPPORTED
	 || error == ERROR_CALL_NOT_IMPLEMENTED
	 || error == ERROR_PRIVILEGE_NOT_HELD
	 || error == ERROR_ACCESS_DISABLED_BY_POLICY;
}

static bool
skip_hresult (HRESULT hr)
{
  return skip_error (HRESULT_CODE (hr));
}

static void
print_child_output (const std::string& output)
{
  if (!output.empty ())
    {
      fwrite (output.data (), 1, output.size (), stdout);
      fflush (stdout);
    }
}

static bool
read_available (HANDLE pipe, std::string& output, DWORD& error)
{
  error = ERROR_SUCCESS;
  for (;;)
    {
      DWORD available = 0;
      if (!PeekNamedPipe (pipe, NULL, 0, NULL, &available, NULL))
	{
	  error = GetLastError ();
	  return error == ERROR_BROKEN_PIPE;
	}
      if (!available)
	return true;
      char buffer[4096];
      DWORD read_count = 0;
      if (!ReadFile (pipe, buffer,
		     available < sizeof buffer ? available : sizeof buffer,
		     &read_count, NULL))
	{
	  error = GetLastError ();
	  return error == ERROR_BROKEN_PIPE;
	}
      if (!read_count)
	return true;
      output.append (buffer, read_count);
    }
}

int
wmain ()
{
  std::wstring child = full_path (L"testinst\\bin\\appcontainer-child.exe");
  if (child.empty ())
    {
      fwprintf (stderr, L"Could not resolve the AppContainer child path: %lu\n",
		GetLastError ());
      return 1;
    }
  std::wstring test_root = parent_path (parent_path (child));
  std::wstring dll = parent_path (child) + L"\\cygwin1.dll";
  if (GetFileAttributesW (child.c_str ()) == INVALID_FILE_ATTRIBUTES
      || GetFileAttributesW (dll.c_str ()) == INVALID_FILE_ATTRIBUTES)
    {
      fwprintf (stderr, L"Missing test child or build-tree cygwin1.dll:\n"
		L"  child: %ls\n  dll: %ls\n", child.c_str (), dll.c_str ());
      return 1;
    }

  WCHAR profile_name[96];
  int name_length
    = swprintf (profile_name, 96, L"CygwinTest-%lu-%llu",
		GetCurrentProcessId (), GetTickCount64 ());
  if (name_length < 0 || name_length >= 96)
    {
      fwprintf (stderr, L"Could not generate AppContainer profile name.\n");
      return 1;
    }
  PSID appcontainer_sid = NULL;
  HRESULT hr = CreateAppContainerProfile (profile_name, profile_name,
					  L"Cygwin testsuite AppContainer",
					  NULL, 0, &appcontainer_sid);
  if (FAILED (hr))
    {
      if (skip_hresult (hr))
	{
	  fwprintf (stdout, L"SKIP=Cannot create AppContainer profile "
		    L"(HRESULT 0x%08lx).\n", (ULONG) hr);
	  return 77;
	}
      fwprintf (stderr, L"CreateAppContainerProfile failed: 0x%08lx\n",
		(ULONG) hr);
      return 1;
    }

  int result = 1;
  temporary_acl acl;
  DWORD error = ERROR_SUCCESS;
  if (!grant_ancestor_traverse (test_root, appcontainer_sid, acl, error)
      || !grant_test_files (test_root, child, dll, appcontainer_sid, acl,
			    error))
    {
      DWORD restore_error = acl.restore ();
      if (restore_error != ERROR_SUCCESS)
	{
	  fwprintf (stderr, L"Could not restore test-tree ACL after setup "
		    L"failure (error %lu).\n", restore_error);
	  goto cleanup_profile;
	}
      if (skip_error (error))
	{
	  fwprintf (stdout, L"SKIP=Cannot grant AppContainer access to test "
		    L"runtime (error %lu).\n", error);
	  result = 77;
	}
      else
	fwprintf (stderr, L"Could not grant AppContainer access to test "
		  L"runtime (error %lu).\n", error);
      goto cleanup_profile;
    }

  {
    SECURITY_ATTRIBUTES pipe_security = { sizeof pipe_security, NULL, TRUE };
    HANDLE output_read = NULL;
    HANDLE output_write = NULL;
    HANDLE input = NULL;
    if (!CreatePipe (&output_read, &output_write, &pipe_security, 0))
      {
	fwprintf (stderr, L"CreatePipe failed: %lu\n", GetLastError ());
	goto cleanup_acl;
      }
    input = CreateFileW (L"NUL", GENERIC_READ,
			 FILE_SHARE_READ | FILE_SHARE_WRITE, &pipe_security,
			 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (input == INVALID_HANDLE_VALUE)
      {
	fwprintf (stderr, L"Could not open NUL for child stdin: %lu\n",
		  GetLastError ());
	CloseHandle (output_read);
	CloseHandle (output_write);
	goto cleanup_acl;
      }
    if (!SetHandleInformation (output_read, HANDLE_FLAG_INHERIT, 0))
      {
	fwprintf (stderr, L"SetHandleInformation failed: %lu\n",
		  GetLastError ());
	CloseHandle (input);
	CloseHandle (output_read);
	CloseHandle (output_write);
	goto cleanup_acl;
      }

    STARTUPINFOEXW startup = {};
    startup.StartupInfo.cb = sizeof startup;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = input;
    startup.StartupInfo.hStdOutput = output_write;
    startup.StartupInfo.hStdError = output_write;

    SIZE_T attr_size = 0;
    InitializeProcThreadAttributeList (NULL, 2, 0, &attr_size);
    if (!attr_size)
      {
	DWORD init_error = GetLastError ();
	if (skip_error (init_error))
	  {
	    fwprintf (stdout, L"SKIP=AppContainer process attributes are not "
		      L"available (error %lu).\n", init_error);
	    result = 77;
	  }
	else
	  fwprintf (stderr, L"AppContainer process attributes are unavailable: "
		    L"%lu\n", init_error);
	CloseHandle (input);
	CloseHandle (output_read);
	CloseHandle (output_write);
	goto cleanup_acl;
      }
    std::vector<BYTE> attr_storage (attr_size);
    startup.lpAttributeList
      = (LPPROC_THREAD_ATTRIBUTE_LIST) attr_storage.data ();
    if (!InitializeProcThreadAttributeList (startup.lpAttributeList, 2, 0,
					    &attr_size))
      {
	DWORD init_error = GetLastError ();
	if (skip_error (init_error))
	  {
	    fwprintf (stdout, L"SKIP=AppContainer process attributes are not "
		      L"available (error %lu).\n", init_error);
	    result = 77;
	  }
	else
	  fwprintf (stderr, L"InitializeProcThreadAttributeList failed: %lu\n",
		    init_error);
	CloseHandle (input);
	CloseHandle (output_read);
	CloseHandle (output_write);
	goto cleanup_acl;
      }

    SECURITY_CAPABILITIES capabilities = {};
    capabilities.AppContainerSid = appcontainer_sid;
    HANDLE inherited[] = { output_write, input };
    bool attrs_ok
      = UpdateProcThreadAttribute (startup.lpAttributeList, 0,
				   PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
				   &capabilities, sizeof capabilities,
				   NULL, NULL)
	&& UpdateProcThreadAttribute (startup.lpAttributeList, 0,
				      PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
				      inherited, sizeof inherited, NULL, NULL);
    if (!attrs_ok)
      {
	DWORD update_error = GetLastError ();
	DeleteProcThreadAttributeList (startup.lpAttributeList);
	CloseHandle (input);
	CloseHandle (output_read);
	CloseHandle (output_write);
	if (skip_error (update_error))
	  {
	    fwprintf (stdout, L"SKIP=AppContainer process attributes are not "
		      L"supported (error %lu).\n", update_error);
	    result = 77;
	  }
	else
	  fwprintf (stderr, L"Could not configure AppContainer process "
		    L"attributes (error %lu).\n", update_error);
	goto cleanup_acl;
      }

    std::wstring command = quote_argument (child);
    std::vector<WCHAR> command_line (command.begin (), command.end ());
    command_line.push_back (L'\0');
    if (!SetEnvironmentVariableW (L"CYGWIN_TESTING", L"1"))
      {
	fwprintf (stderr, L"SetEnvironmentVariable(CYGWIN_TESTING) failed: "
		  L"%lu\n", GetLastError ());
	DeleteProcThreadAttributeList (startup.lpAttributeList);
	CloseHandle (input);
	CloseHandle (output_read);
	CloseHandle (output_write);
	goto cleanup_acl;
      }

    PROCESS_INFORMATION process = {};
    BOOL created
      = CreateProcessW (child.c_str (), command_line.data (), NULL, NULL, TRUE,
			EXTENDED_STARTUPINFO_PRESENT, NULL,
			parent_path (child).c_str (), &startup.StartupInfo,
			&process);
    DWORD create_error = GetLastError ();
    DeleteProcThreadAttributeList (startup.lpAttributeList);
    CloseHandle (input);
    CloseHandle (output_write);
    if (!created)
      {
	CloseHandle (output_read);
	if (skip_error (create_error))
	  {
	    fwprintf (stdout, L"SKIP=Host denied AppContainer child launch "
		      L"(error %lu).\n", create_error);
	    result = 77;
	  }
	else
	  fwprintf (stderr, L"CreateProcess(AppContainer child) failed: %lu\n",
		    create_error);
	goto cleanup_acl;
      }

    std::string output;
    ULONGLONG deadline = GetTickCount64 () + 30000;
    bool timed_out = false;
    bool output_failed = false;
    DWORD output_error = ERROR_SUCCESS;
    for (;;)
      {
	if (!read_available (output_read, output, output_error))
	  {
	    fwprintf (stderr, L"Could not read AppContainer child output: %lu\n",
		      output_error);
	    output_failed = true;
	    TerminateProcess (process.hProcess, 1);
	    WaitForSingleObject (process.hProcess, INFINITE);
	    break;
	  }
	DWORD wait = WaitForSingleObject (process.hProcess, 50);
	if (wait == WAIT_OBJECT_0)
	  {
	    if (!read_available (output_read, output, output_error))
	      {
		fwprintf (stderr,
			  L"Could not read AppContainer child output: %lu\n",
			  output_error);
		output_failed = true;
	      }
	    break;
	  }
	if (wait == WAIT_FAILED)
	  {
	    fwprintf (stderr, L"WaitForSingleObject failed: %lu\n",
		      GetLastError ());
	    TerminateProcess (process.hProcess, 1);
	    WaitForSingleObject (process.hProcess, INFINITE);
	    break;
	  }
	if (GetTickCount64 () >= deadline)
	  {
	    timed_out = true;
	    TerminateProcess (process.hProcess, 1);
	    WaitForSingleObject (process.hProcess, INFINITE);
	    if (!read_available (output_read, output, output_error))
	      {
		fwprintf (stderr,
			  L"Could not read AppContainer child output: %lu\n",
			  output_error);
		output_failed = true;
	      }
	    break;
	  }
      }
      {
	DWORD exit_code = 1;
	GetExitCodeProcess (process.hProcess, &exit_code);
	print_child_output (output);
	if (timed_out)
	  fwprintf (stderr, L"AppContainer child timed out.\n");
	else if (output_failed)
	  result = 1;
	else if (!is_appcontainer (process.hProcess))
	  fwprintf (stderr, L"Child process token is not an AppContainer.\n");
	else if (exit_code != 0)
	  fwprintf (stderr, L"AppContainer child exited with status %lu.\n",
		    exit_code);
	else
	  result = 0;
      }
    CloseHandle (process.hThread);
    CloseHandle (process.hProcess);
    CloseHandle (output_read);
  }

cleanup_acl:
  {
    DWORD restore_error = acl.restore ();
    if (restore_error != ERROR_SUCCESS)
      {
	fwprintf (stderr, L"Could not restore test-tree ACL (error %lu).\n",
		  restore_error);
	result = 1;
      }
  }
cleanup_profile:
  {
    HRESULT cleanup_hr = DeleteAppContainerProfile (profile_name);
    if (FAILED (cleanup_hr))
      {
	fwprintf (stderr, L"DeleteAppContainerProfile failed: 0x%08lx\n",
		  (ULONG) cleanup_hr);
	result = 1;
      }
    FreeSid (appcontainer_sid);
  }
  return result;
}
