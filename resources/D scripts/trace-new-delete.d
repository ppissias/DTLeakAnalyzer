#!/usr/sbin/dtrace -s

/* 
 * Original version from : 
	# https://blogs.oracle.com/openomics/investigating-memory-leaks-with-dtrace 
	
	adapted to trace also delete and new[] operations. 
	Removed internal logic of the d program as the java analyzer performes an analysis of the traces.
	
*/ 

#pragma D option quiet
#pragma D option aggrate=100us
#pragma D option aggsize=1g
#pragma D option bufpolicy=fill
#pragma D option bufsize=1g

/*
__1c2K6Fpv_v_ == void operator delete[](void*)
__1c2N6FI_pv_ == void*operator new[](unsigned)
__1c2k6Fpv_v_ == void operator delete(void*)
__1c2n6FI_pv_ == void*operator new(unsigned)   
*/

/* operator new */
pid$1::__1c2n6FI_pv_:entry
{
   /* log allocation size */	
   self->size = arg0;
}

pid$1::__1c2n6FI_pv_:return
/self->size/
{
   /* print details of the allocation */   
   printf("<__%i;%Y;%d;new;0x%x;%d;\n", i++, walltimestamp, tid, arg1, self->size);
   ustack(50);
   printf("__>\n\n");
   self->size=0;
}


/* delete operator */ 
pid$1::__1c2k6Fpv_v_:entry
{   
   /* print details of the deallocation */
   printf("<__%i;%Y;%d;delete;0x%x\n",i++, walltimestamp, tid, arg0);
   ustack(50);
   printf("__>\n\n");    
}


/* operator new[] , we log that this was created with new[]*/
pid$1::__1c2N6FI_pv_:entry
{
   self->sizeArray = arg0;
}

pid$1::__1c2N6FI_pv_:return
/self->sizeArray/
{   
   /* print details of the allocation */
   printf("<__%i;%Y;%d;new[];0x%x;%d;\n", i++, walltimestamp, tid, arg1, self->sizeArray);
   ustack(50);
   printf("__>\n\n");
   self->sizeArray=0;
}


/* delete[] operator */
pid$1::__1c2K6Fpv_v_:entry
{
   /* print details of the deallocation */
   printf("<__%i;%Y;%d;delete[];0x%x\n",i++, walltimestamp, tid, arg0);
   ustack(50);
   printf("__>\n\n");   
}


END
{
   printf("== FINISHED ==\n\n");
} 