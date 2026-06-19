program mai_fortran_runtime_test
    use iso_c_binding
    implicit none

    type, bind(C) :: mai_stats
        integer(c_int) :: enabled
        integer(c_int) :: configured
        integer(c_int) :: config_error
        integer(c_size_t) :: threshold
        integer(c_size_t) :: arena_size
        integer(c_size_t) :: target_rss
        integer(c_size_t) :: current_rss_bytes
        integer(c_size_t) :: high_water_rss_bytes
        integer(c_size_t) :: arena_segments
        integer(c_size_t) :: arena_bytes
        integer(c_size_t) :: managed_bytes_total
        integer(c_size_t) :: pass_through_bytes_total
        integer(c_size_t) :: live_managed_bytes
        integer(c_size_t) :: high_water_managed_bytes
        integer(c_size_t) :: managed_allocations
        integer(c_size_t) :: pass_through_allocations
        integer(c_size_t) :: managed_frees
        integer(c_size_t) :: reclaim_calls
        integer(c_size_t) :: policy_reclaim_calls
        integer(c_size_t) :: reclaimed_bytes
        integer(c_size_t) :: mmap_calls
        integer(c_size_t) :: munmap_calls
        integer(c_size_t) :: mremap_calls
        integer(c_size_t) :: brk_calls
        integer(c_size_t) :: sbrk_calls
        integer(c_size_t) :: profile_sites
        integer(c_size_t) :: hotness_samples
        integer(c_size_t) :: hotness_sampled_pages
        integer(c_size_t) :: hotness_resident_pages
        integer(c_size_t) :: allocator_hook_mode
        integer(c_size_t) :: allocator_libc_patches
        integer(c_size_t) :: allocator_preload_calls
        integer(c_size_t) :: allocator_frida_calls
        integer(c_size_t) :: excluded_ranges
        integer(c_size_t) :: excluded_bytes
        integer(c_size_t) :: exclusion_events
        integer(c_size_t) :: exclusion_release_events
        integer(c_size_t) :: reclaim_skipped_excluded
        integer(c_size_t) :: reclaim_skipped_excluded_bytes
        integer(c_size_t) :: safety_hook_patches
        integer(c_size_t) :: max_rss
        integer(c_size_t) :: memory_cap_reclaim_calls
        integer(c_size_t) :: memory_cap_failures
        integer(c_size_t) :: anon_allocations
        integer(c_size_t) :: file_allocations
        integer(c_size_t) :: migrated_to_file_bytes
        integer(c_size_t) :: promoted_to_anon_bytes
        integer(c_size_t) :: uffd_pager_available
        integer(c_size_t) :: uffd_pager_allocations
        integer(c_size_t) :: uffd_faults
        integer(c_size_t) :: uffd_evictions
        integer(c_size_t) :: uffd_resident_bytes
        integer(c_size_t) :: uffd_fallbacks
    end type mai_stats

    interface
        function mai_get_stats_sized(stats, stats_size) bind(C, name="mai_get_stats_sized") result(rc)
            import :: c_int, c_size_t, mai_stats
            type(mai_stats), intent(out) :: stats
            integer(c_size_t), value :: stats_size
            integer(c_int) :: rc
        end function mai_get_stats_sized

        function c_malloc(size) bind(C, name="malloc") result(ptr)
            import :: c_ptr, c_size_t
            integer(c_size_t), value :: size
            type(c_ptr) :: ptr
        end function c_malloc

        subroutine c_free(ptr) bind(C, name="free")
            import :: c_ptr
            type(c_ptr), value :: ptr
        end subroutine c_free
    end interface

    type(mai_stats) :: before
    type(mai_stats) :: after_alloc
    type(mai_stats) :: after_free
    type(mai_stats) :: before_native
    type(mai_stats) :: after_native_alloc
    type(mai_stats) :: after_native_free
    type(c_ptr) :: raw
    integer(c_int) :: rc
    integer(c_size_t), parameter :: bytes = 8192_c_size_t
    integer(c_size_t), parameter :: native_bytes = 16384_c_size_t
    integer(c_signed_char), pointer :: values(:)
    real(c_double), allocatable :: native(:)
    integer :: alloc_stat
    integer :: i

    rc = mai_get_stats_sized(before, c_sizeof(before))
    if (rc /= 0) error stop 1

    raw = c_malloc(bytes)
    if (.not. c_associated(raw)) error stop 2

    call c_f_pointer(raw, values, [8192])
    do i = 1, 8192
        values(i) = int(mod(i, 127), c_signed_char)
    end do
    do i = 1, 8192
        if (values(i) /= int(mod(i, 127), c_signed_char)) then
            call c_free(raw)
            error stop 3
        end if
    end do

    rc = mai_get_stats_sized(after_alloc, c_sizeof(after_alloc))
    if (rc /= 0) then
        call c_free(raw)
        error stop 4
    end if
    if (after_alloc%managed_allocations <= before%managed_allocations .or. &
        after_alloc%managed_bytes_total < before%managed_bytes_total + bytes .or. &
        after_alloc%live_managed_bytes < before%live_managed_bytes + bytes .or. &
        (after_alloc%anon_allocations <= before%anon_allocations .and. &
         after_alloc%file_allocations <= before%file_allocations .and. &
         after_alloc%arena_segments == 0_c_size_t)) then
        call c_free(raw)
        error stop 5
    end if

    call c_free(raw)
    rc = mai_get_stats_sized(after_free, c_sizeof(after_free))
    if (rc /= 0) error stop 6
    if (after_free%managed_frees <= before%managed_frees .or. &
        after_free%live_managed_bytes /= before%live_managed_bytes) error stop 7

    before_native = after_free

    allocate(native(2048), stat=alloc_stat)
    if (alloc_stat /= 0) error stop 8

    do i = 1, 2048
        native(i) = real(i, c_double) * 0.5_c_double
    end do
    do i = 1, 2048
        if (native(i) /= real(i, c_double) * 0.5_c_double) then
            deallocate(native)
            error stop 9
        end if
    end do

    rc = mai_get_stats_sized(after_native_alloc, c_sizeof(after_native_alloc))
    if (rc /= 0) then
        deallocate(native)
        error stop 10
    end if
    if (after_native_alloc%managed_allocations <= before_native%managed_allocations .or. &
        after_native_alloc%managed_bytes_total < before_native%managed_bytes_total + native_bytes .or. &
        after_native_alloc%live_managed_bytes < before_native%live_managed_bytes + native_bytes .or. &
        (after_native_alloc%anon_allocations <= before_native%anon_allocations .and. &
         after_native_alloc%file_allocations <= before_native%file_allocations .and. &
         after_native_alloc%arena_segments == 0_c_size_t)) then
        deallocate(native)
        error stop 11
    end if

    deallocate(native)
    rc = mai_get_stats_sized(after_native_free, c_sizeof(after_native_free))
    if (rc /= 0) error stop 12
    if (after_native_free%managed_frees <= before_native%managed_frees .or. &
        after_native_free%live_managed_bytes /= before_native%live_managed_bytes) error stop 13
end program mai_fortran_runtime_test
