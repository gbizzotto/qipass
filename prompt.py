import sys
import copy
import os

class _Getch:
	"""Gets a single character from standard input.  Does not echo to the
screen."""
	def __init__(self):
		try:
			self.impl = _GetchWindows()
		except ImportError:
			self.impl = _GetchUnix()

	def __call__(self): return self.impl()


class _GetchUnix:
	def __init__(self):
		import tty, sys

	def __call__(self):
		import sys, tty, termios
		fd = sys.stdin.fileno()
		old_settings = termios.tcgetattr(fd)
		try:
			tty.setraw(fd)
			return os.read(fd, 1024).decode()
		finally:
			termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
		return ch


class _GetchWindows:
	def __init__(self):
		import msvcrt

	def __call__(self):
		import msvcrt
		c = msvcrt.getch()
		if c == '\000' or c == '\xe0':
			c.append(msvcrt.getch())
		return c

getch = _Getch()


ECHO = 0
NONE = 1
HIDE = 2
LAST = 3
WIPE = 4

def input(prompt='', echo=ECHO, history=None):
	# avoid the persistent parameter
	if history is None:
		history = []
	
	# prompt
	sys.stdout.write("\r"+prompt)
	sys.stdout.flush()
	alternate_history = copy.deepcopy(history)
	i = len(alternate_history)
	alternate_history.append('')	

	# helper functions
	def stars_on_exit():
		if echo == WIPE or echo == LAST:
			sys.stdout.write("\r"+prompt+'*'*len(alternate_history[i]))
			sys.stdout.flush()
		print('')

	def blanks():
		sys.stdout.write("\r"+prompt+' '*len(alternate_history[i]))
		sys.stdout.flush()

	def reprint():
		sys.stdout.write("\r"+prompt)
		if echo == ECHO or echo == WIPE:
			sys.stdout.write(alternate_history[i])
		elif echo == HIDE or echo == LAST:
			sys.stdout.write('*'*len(alternate_history[i]))
		sys.stdout.flush()

	# Processing the keyboard input
	while True:
		x = getch()
		if len(x) == 0:
			# might be EOF
			stars_on_exit()
			sys.exit(0)
		c = ord(x[0])
		if c == 3 or c == 4:
			# ctrl-c, ctrl-d
			stars_on_exit()
			sys.exit(0)
		if c == 10 or c == 13:
			break
		elif c < 127 and c > 31:
			# Normal char pressed
			alternate_history[i] = alternate_history[i] + x
			if echo == ECHO or echo == WIPE:
				sys.stdout.write(x)
			if echo == HIDE:
				sys.stdout.write('*'*len(x))
			elif echo == LAST:
				sys.stdout.write("\r"+prompt)
				sys.stdout.write('*'*(len(alternate_history[i])-1))
				sys.stdout.write(alternate_history[i][-1])
			sys.stdout.flush()
		elif c == 127:
			# Backspace pressed
			if len(alternate_history[i]) == 0:
				continue
			blanks()
			alternate_history[i] = alternate_history[i][:-1]
			reprint()
		elif x == '\x1b':
			# ESC pressed
			stars_on_exit()
			return None
		elif x == '\x1b[A':
			# Up arrow
			if i == 0:
				continue
			blanks()
			i = i-1
			reprint()
		elif x == '\x1b[B':
			# Down arrow
			if i >= len(alternate_history)-1:
				continue
			blanks()
			i = i+1
			reprint()

	# return on enter
	stars_on_exit()
	if len(history) == 0 or history[-1] != alternate_history[i]:
		history.append(alternate_history[i])
	return alternate_history[i]

if __name__ == "__main__":
	h = []
	while True:
		print(input("prompt:", echo=ECHO, history=h))
