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
    end type mai_stats

    interface
        function mai_get_stats(stats) bind(C, name="mai_get_stats") result(rc)
            import :: c_int, mai_stats
            type(mai_stats), intent(out) :: stats
            integer(c_int) :: rc
        end function mai_get_stats

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
    type(c_ptr) :: raw
    integer(c_int) :: rc
    integer(c_size_t), parameter :: bytes = 8192_c_size_t
    integer(c_signed_char), pointer :: values(:)
    integer :: i

    rc = mai_get_stats(before)
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

    rc = mai_get_stats(after_alloc)
    if (rc /= 0) then
        call c_free(raw)
        error stop 4
    end if
    if (after_alloc%managed_allocations <= before%managed_allocations) then
        call c_free(raw)
        error stop 5
    end if

    call c_free(raw)
    rc = mai_get_stats(after_free)
    if (rc /= 0) error stop 6
    if (after_free%live_managed_bytes /= before%live_managed_bytes) error stop 7
end program mai_fortran_runtime_test
