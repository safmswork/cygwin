/* Share socket state across dup/fork/exec, but not object namespaces. */

#include <windows.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
fail (const char *message)
{
  perror (message);
  exit (1);
}

static int
check_namespace (int fd)
{
  char executable[MAX_PATH];
  char command[MAX_PATH + 32];
  DWORD length = GetModuleFileNameA (NULL, executable, sizeof executable);
  if (!length || length >= sizeof executable)
    return 1;
  snprintf (command, sizeof command, "\"%s\" --other-namespace", executable);

  /* A native launch avoids inheriting Cygwin's process information. */
  const char *testing = getenv ("CYGWIN_TESTING");
  if (!SetEnvironmentVariableA ("CYGWIN_TESTING",
			       testing && *testing ? NULL : "1"))
    return 1;
  STARTUPINFOA startup = { .cb = sizeof startup };
  PROCESS_INFORMATION process;
  BOOL created = CreateProcessA (executable, command, NULL, NULL, FALSE, 0,
				 NULL, NULL, &startup, &process);
  BOOL restored = SetEnvironmentVariableA ("CYGWIN_TESTING", testing);
  if (!created)
    {
      fputs ("Could not launch the other socket namespace\n", stderr);
      return 1;
    }
  CloseHandle (process.hThread);
  DWORD wait = WaitForSingleObject (process.hProcess, 20000);
  DWORD status = 1;
  if (wait == WAIT_OBJECT_0)
    GetExitCodeProcess (process.hProcess, &status);
  else
    {
      TerminateProcess (process.hProcess, 1);
      WaitForSingleObject (process.hProcess, INFINITE);
    }
  CloseHandle (process.hProcess);
  if (!restored || wait != WAIT_OBJECT_0 || status)
    {
      fputs ("Other socket namespace failed\n", stderr);
      return 1;
    }
  if (fcntl (fd, F_GETOWN) != getpid ())
    {
      fputs ("Other namespace overwrote a live socket's event state\n",
	     stderr);
      return 1;
    }
  return 0;
}

int
main (int argc, char **argv)
{
  alarm (30);
  if (argc == 2 && !strcmp (argv[1], "--other-namespace"))
    {
      for (int i = 0; i < 4096; ++i)
	{
	  int fd = socket (AF_INET, SOCK_DGRAM, 0);
	  if (fd == -1)
	    fail ("socket in other namespace");
	  close (fd);
	}
      return 0;
    }
  if (argc == 3 && !strcmp (argv[1], "--exec"))
    {
      int fd = atoi (argv[2]);
      if (fcntl (fd, F_GETOWN) != getpid ())
	{
	  fputs ("Socket owner was not preserved across exec\n", stderr);
	  return 1;
	}
      if (fcntl (fd, F_SETOWN, getppid ()) == -1)
	fail ("F_SETOWN after exec");
      return 0;
    }

  int fd = socket (AF_INET, SOCK_DGRAM, 0);
  if (fd == -1)
    fail ("socket");
  if (fcntl (fd, F_SETOWN, 0) == -1)
    fail ("F_SETOWN");

  pid_t child = fork ();
  if (child == -1)
    fail ("fork");
  if (!child)
    {
      if (fcntl (fd, F_SETOWN, getpid ()) == -1)
	fail ("F_SETOWN after fork");
      int duplicate = dup (fd);
      if (duplicate == -1)
	fail ("dup");
      if (fcntl (duplicate, F_GETOWN) != getpid ())
	{
	  fputs ("Duplicated socket does not share its owner\n", stderr);
	  return 1;
	}
      close (duplicate);
      char fdstr[32];
      snprintf (fdstr, sizeof fdstr, "%d", fd);
      execl (argv[0], argv[0], "--exec", fdstr, (char *) NULL);
      fail ("exec");
    }

  int status;
  if (waitpid (child, &status, 0) != child)
    fail ("waitpid");
  if (!WIFEXITED (status) || WEXITSTATUS (status))
    {
      fputs ("Socket child failed\n", stderr);
      return 1;
    }
  if (fcntl (fd, F_GETOWN) != getpid ())
    {
      fputs ("Parent did not observe the child's socket owner update\n",
	     stderr);
      return 1;
    }
  int result = check_namespace (fd);
  close (fd);
  return result;
}
