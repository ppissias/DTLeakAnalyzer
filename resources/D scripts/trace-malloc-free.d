#!/usr/sbin/dtrace -s

/* 
 * Original version from : 
	# https://blogs.oracle.com/openomics/investigating-memory-leaks-with-dtrace 
	
	adapted to only trace malloc and free operations 
	Removed internal logic of the d program as the java analyzer performes an analysis of the traces.
*/ 

#pragma D option quiet
#pragma D option aggrate=100us
#pragma D option aggsize=1g
#pragma D option bufpolicy=fill
#pragma D option bufsize=1g

pid$1::malloc:entry
{
   self->size = arg0;
}

pid$1::malloc:return
/self->size/
{
   /* print details of the allocation */
   printf("<__%i;%Y;%d;malloc;0x%x;%d;\n",i++, walltimestamp, tid, arg1, self->size);
   ustack(50);
   printf("__>\n\n");
   self->size=0;
}

pid$1::free:entry
{
   /* print details of the deallocation */
   printf("<__%i;%Y;%d;free;0x%x__>\n",i++, walltimestamp, tid, arg0);
}

END
{
   printf("== FINISHED ==\n\n");
} 