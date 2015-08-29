erlang*:::nif-entry
{
	funcall_entry_ts[cpu, copyinstr(arg1)] = timestamp;
}

erlang*:::nif-return
{
	@time[cpu, copyinstr(arg1)] = lquantize((timestamp - funcall_entry_ts[cpu, copyinstr(arg1)] ), 0, 60000, 1000);
}
