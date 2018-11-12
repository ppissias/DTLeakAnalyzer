#!/usr/sbin/dtrace -s

/* 
* Thanks to : 
* 	# http://www.brendangregg.com/Solaris/memoryflamegraphs.html
*
* Dtrace script that logs all call stacks that caused a process memory increase
* The output of the script is further processed as described in 
* https://github.com/ppissias/DTLeakAnalyzer
*
* Author Petros Pissias
*/ 

#pragma D option quiet

#!/usr/sbin/dtrace -s

pid$1::brk:entry
{
	self->trace = 1;
	self->newaddr = arg0;
}

pid$1::brk:return
/self->trace == 1/
{
	/* log the memory allocation */
	printf("<__%i;%Y;%d;brk;0x%x;%d;\n", i++, walltimestamp, tid, self->newaddr, arg1);
	ustack(50);
	printf("__>\n\n");
	
	self->trace = 0;
	self->newaddr = 0;
}

pid$1::sbrk:entry
{
	self->trace = 1;
	self->incrsize = arg0;
}

pid$1::sbrk:return
/self->trace == 1/
{
	/* log the memory allocation */
	printf("<__%i;%Y;%d;sbrk;0x%x;%d;\n", i++, walltimestamp, tid, arg1, self->incrsize);
	ustack(50);
	printf("__>\n\n");
	
	self->trace = 0;
	self->incrsize = 0;
}
