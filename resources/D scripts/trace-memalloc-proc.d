#!/usr/sbin/dtrace -s

/*
* Dtrace script that logs the number of times call stacks allocated or freed memory
* The output of the script is further processed as described in 
* https://github.com/ppissias/DTLeakAnalyzer
*
* Adapt the aggsize, aggsize and bufsize parameters accordingly if needed.  
* Author Petros Pissias
*/ 

#pragma D option quiet
#pragma D option aggrate=100us
#pragma D option aggsize=100m
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
	@allocstacks[ustack(50)] = count();
	@counts["created"] = count();
	counts["pending"]++;	

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
/ (self->trace == 1) && (self->size == 0)/
{
	/* this is same as free, size=0 */
	@deallocstacks[ustack(50)] = count();
	@counts["deleted"] = count();
	counts["pending"]--;
	
	self->trace = 0;
	self->size = 0;
	self->oldptr = 0;
}

pid$1::realloc:return
/ (self->trace == 1) && (self->size > 0)/
{
	/* this is a deallocation and a new allocation */
	@deallocstacks[ustack(50)] = count();
	@allocstacks[ustack(50)] = count();
	
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
	/* log the memory allocation */
	@allocstacks[ustack(50)] = count();
	@counts["created"] = count();
	counts["pending"]++;
	
	self->trace = 0;
	self->size = 0;
	self->nelements = 0;	
}



pid$1::free:entry
{
	@deallocstacks[ustack(50)] = count();
	@counts["deleted"] = count();
	counts["pending"]--;
}

END
{
	printf("== FINISHED ==\n\n");
	printf("== allocation stacks ==\n\n");
	printa(@allocstacks);
	printf("\n== deallocation stacks ==\n\n");
	printa(@deallocstacks);
	printf("\n== mem allocations vs deletions ==\n\n");
	printa(@counts);
	printf("number of allocations - number of deallocations: %d",counts["pending"]);
} 
