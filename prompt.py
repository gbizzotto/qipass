import sys
import click
import copy

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
	def stars():
		if echo == WIPE or echo == LAST:
			sys.stdout.write("\r"+prompt+'*'*len(alternate_history[i]))
			sys.stdout.flush()
		print('')

	def blanks():
		sys.stdout.write("\r"+prompt+' '*len(alternate_history[i]))

	def reprint():
		sys.stdout.write("\r"+prompt)
		if echo == ECHO or echo == WIPE:
			sys.stdout.write(alternate_history[i])
		elif echo == HIDE or echo == LAST:
			sys.stdout.write('*'*len(alternate_history[i]))
		sys.stdout.flush()

	# Processing the keyboard input
	while True:
		x = click.getchar()
		c = ord(x[0])
		if c == 10 or c == 13:
			break
		elif c < 127 and c > 31:
			# Normal char pressed
			alternate_history[i] = alternate_history[i] + x
			if echo == ECHO or echo == WIPE:
				sys.stdout.write(x)
			if echo == HIDE:
				sys.stdout.write('*')
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
			stars()
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
	stars()
	if len(history) == 0 or history[-1] != alternate_history[i]:
		history.append(alternate_history[i])
	return alternate_history[i]

if __name__ == "__main__":
	h = []
	while True:
		print(input("prompt:", echo=ECHO, history=h))
