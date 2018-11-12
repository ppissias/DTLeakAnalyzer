#!/usr/sbin/dtrace -s

/* 
* Thanks to : 
* 	# http://www.brendangregg.com/Solaris/memoryflamegraphs.html
*	# http://ewaldertl.blogspot.com/2010/09/debugging-memory-leaks-with-dtrace-and.html
*	
* Dtrace script that logs all
* malloc, calloc, realloc and free calls and their call stacks
*
* The output of the script is further processed as described in 
* https://github.com/ppissias/DTLeakAnalyzer
*
* Adapt the aggsize, aggsize and bufsize parameters accordingly if needed.  
* Author Petros Pissias
*/ 

#pragma D option quiet
#pragma D option aggrate=100us
#pragma D option bufpolicy=fill
#pragma D option bufsize=100m


#!/usr/sbin/dtrace -s

pid$1::malloc:entry
{
	self->trace = 1;
	self->size = arg0;
}

pid$1::malloc:return
/self->trace == 1/
{
	/* log the memory allocation */
	printf("<__%i;%Y;%d;malloc;0x%x;%d;\n", i++, walltimestamp, tid, arg1, self->size);
	ustack(50);
	printf("__>\n\n");
	
	self->trace = 0;
	self->size = 0;
}


pid$1::realloc:entry
{
	self->trace = 1;
	self->size = arg1;
	self->oldptr = arg0;
}

pid$1::realloc:return
/self->trace == 1/
{
	/* log the memory re-allocation. Log the old memory address and the new memory address */
	printf("<__%i;%Y;%d;realloc;0x%x;0x%x;%d;\n", i++, walltimestamp, tid, self->oldptr, arg1, self->size);
	ustack(50);
	printf("__>\n\n");
	
	self->trace = 0;
	self->size = 0;
	self->oldptr = 0;
}

pid$1::calloc:entry
{
	self->trace = 1;
	self->size = arg1;
	self->nelements = arg0;
}

pid$1::calloc:return
/self->trace == 1/
{
	/* log the memory allocation with the total size*/
	printf("<__%i;%Y;%d;calloc;0x%x;%d;\n", i++, walltimestamp, tid, arg1, self->size*self->nelements);
	ustack(50);
	printf("__>\n\n");

	self->trace = 0;
	self->size = 0;
	self->nelements = 0;
}

pid$1::free:entry
{
	printf("<__%i;%Y;%d;free;0x%x;\n", i++, walltimestamp, tid, arg0);
	ustack(50);
	printf("__>\n\n");
}

END
{
   printf("== FINISHED ==\n\n");
} 

