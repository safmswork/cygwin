/* Exercise runtime initialization and named-object locking in AppContainer. */

#include <windows.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <sys/file.h>
#include <unistd.h>

static int
is_appcontainer (void)
{
  HANDLE token;
  DWORD value = 0;
  DWORD size = 0;

  if (!OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY, &token))
    {
      fprintf (stderr, "OpenProcessToken failed: %lu\n",
	       (unsigned long) GetLastError ());
      return -1;
    }
  BOOL ok = GetTokenInformation (token, TokenIsAppContainer, &value,
				 sizeof value, &size);
  DWORD error = ok ? ERROR_SUCCESS : GetLastError ();
  CloseHandle (token);
  if (!ok)
    {
      fprintf (stderr, "GetTokenInformation(TokenIsAppContainer) failed: "
	       "%lu\n", (unsigned long) error);
      return -1;
    }
  return value != 0;
}

static int
check_runtime_dll (void)
{
  WCHAR actual[MAX_PATH];
  WCHAR executable[MAX_PATH];
  HMODULE module = GetModuleHandleW (L"cygwin1.dll");
  if (!module
      || !GetModuleFileNameW (module, actual, sizeof actual / sizeof actual[0]))
    {
      fprintf (stderr, "Could not locate loaded cygwin1.dll: %lu\n",
	       (unsigned long) GetLastError ());
      return -1;
    }
  if (!GetModuleFileNameW (NULL, executable,
			   sizeof executable / sizeof executable[0]))
    {
      fprintf (stderr, "Could not locate test executable: %lu\n",
	       (unsigned long) GetLastError ());
      return -1;
    }

  WCHAR actual_full[MAX_PATH];
  WCHAR executable_full[MAX_PATH];
  DWORD actual_len = GetFullPathNameW (actual, MAX_PATH, actual_full, NULL);
  DWORD executable_len
    = GetFullPathNameW (executable, MAX_PATH, executable_full, NULL);
  if (!actual_len || actual_len >= MAX_PATH
      || !executable_len || executable_len >= MAX_PATH)
    {
      fprintf (stderr, "Could not normalize runtime paths.\n");
      return -1;
    }

  WCHAR *actual_slash = wcsrchr (actual_full, L'\\');
  WCHAR *executable_slash = wcsrchr (executable_full, L'\\');
  if (!actual_slash || !executable_slash
      || CompareStringOrdinal (actual_slash + 1, -1, L"cygwin1.dll", -1,
			       TRUE) != CSTR_EQUAL)
    {
      fwprintf (stderr, L"Unexpected runtime DLL path: %ls\n", actual_full);
      return -1;
    }
  *actual_slash = L'\0';
  *executable_slash = L'\0';
  if (CompareStringOrdinal (actual_full, -1, executable_full, -1, TRUE)
      != CSTR_EQUAL)
    {
      fwprintf (stderr, L"Loaded cygwin1.dll is not beside the test "
	       L"executable.\n  loaded: %ls\n  executable: %ls\n",
	       actual_full, executable_full);
      return -1;
    }
  return 0;
}

int
main (int argc, char **argv)
{
  (void) argv;
  if (argc != 1)
    {
      fprintf (stderr, "usage: appcontainer-child\n");
      return 2;
    }

  int appcontainer = is_appcontainer ();
  if (appcontainer < 0)
    return 1;
  if (!appcontainer)
    {
      fprintf (stderr, "Child is not running in an AppContainer.\n");
      return 1;
    }
  if (check_runtime_dll ())
    return 1;

  int fd = open ("appcontainer-child.exe", O_RDONLY);
  if (fd < 0)
    {
      fprintf (stderr, "open test executable failed: %s\n", strerror (errno));
      return 1;
    }
  if (flock (fd, LOCK_SH | LOCK_NB) < 0)
    {
      fprintf (stderr, "flock shared lock failed: %s\n", strerror (errno));
      close (fd);
      return 1;
    }
  if (flock (fd, LOCK_UN) < 0)
    {
      fprintf (stderr, "flock unlock failed: %s\n", strerror (errno));
      close (fd);
      return 1;
    }
  if (close (fd) < 0)
    {
      fprintf (stderr, "close test executable failed: %s\n", strerror (errno));
      return 1;
    }

  puts ("Cygwin AppContainer startup and named-object locking passed.");
  return 0;
}
